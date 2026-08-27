//! JSON Schema -> `clap::Command`, and `ArgMatches` -> tool arguments.
//!
//! The schema is the single source of truth: it is what the MCP surface publishes,
//! so a CLI derived from it agrees with MCP by construction. Only the handful of
//! things a schema genuinely cannot express (which parameter reads best as a
//! positional, which integers accept `0x`) come from [`CliHints`], and the one
//! value no tool schema contains at all — which session to work on — comes from
//! [`SessionSpec`].
//!
//! Schema constructs that do not map onto a flag are reported rather than
//! silently dropped. The classifier is a **whitelist** ([`Shape`]): it recognises
//! a closed list of constructs and treats everything else as not understood,
//! which is the only form of the promise that holds for schemas nobody has seen
//! yet. A blacklist — asking instead "is this an object?" — would let the 54
//! `ida-headless-mcp` parameters whose schema has *no* `type` sail past every
//! guard into an untyped free-form flag indistinguishable from a real
//! `type: "string"` one, with nothing to tell the user, the implementer or the
//! mapper that a contract had been lost.
//!
//! The tree that comes out is `<bin> tool <name>`, never `<bin> <name>`: the root
//! belongs to the engine's management commands, and clap has no way to report the
//! collision that sharing it would cause. Which names those management commands
//! take is the engine's to say, not ours to guess — see [`EngineCli`].

use std::collections::{BTreeMap, BTreeSet};

use clap::{Arg, ArgAction, ArgMatches, Command};
use serde_json::{Map, Value};

use crate::schema::{deref, effective, is_null_branch, types_of};

use crate::session::SessionSpec;
use crate::{ToolDef, parse_int};

/// The subcommand every derived tool hangs off.
///
/// Engines add their own management commands (`serve`, `mcp`, `status`, …) to the
/// root this module returns. If tools sat there too, clap would resolve two
/// subcommands of one name by keeping the last registered and saying nothing — so
/// an engine with 76 flat tool names could delete its own `status` command by
/// adding a tool called `status`. One extra level makes that impossible.
pub const TOOL_COMMAND: &str = "tool";

/// The management-command names assumed for an engine that does not declare its
/// own. The common management verbs, plus `help` (clap generates one) and
/// `version`.
///
/// This is a *guess*, and [`EngineCli::with_management`] exists because a guess
/// cannot be right: it names commands an engine may not have, and misses the ones
/// it does — rjadx's `decompile`, say, which is nowhere in this list. An engine
/// that knows better says so; this stays as the fallback.
///
/// Nesting under [`TOOL_COMMAND`] already separates the two namespaces, so this is
/// defence in depth: it is what fails loudly if the nesting is ever flattened
/// again, and it keeps `<engine> tool serve` from reading as the management
/// command it is not.
pub const RESERVED: &[&str] = &[
    "batch",
    "capabilities",
    "doctor",
    "help",
    "logs",
    "mcp",
    "serve",
    "sessions",
    "status",
    "tool",
    "version",
];

/// An engine's command tree, before it is built and checked.
///
/// The engine's own commands sit at the root next to [`TOOL_COMMAND`], and only
/// the engine knows what they are called — so it is the engine that tells us,
/// through [`with_management`](Self::with_management), and the check runs against
/// that instead of against [`RESERVED`]'s guess:
///
/// ```text
/// let cli = Toy::vibrev_cli("toy")
///     .with_management(&["mcp"])
///     .command()
///     .subcommand(Command::new("mcp"));
/// assert_management_matches_command(&cli, &["mcp"]);
/// ```
///
/// The tree is deliberately not built until [`command`](Self::command): the checks
/// need the management names, and those arrive after `vibrev_cli()` returns.
/// [`assert_management_matches_command`] is the other half of the check: it runs
/// *after* the engine grafts its Parser tree, so a name that landed only in
/// clap (or only in the declaration) cannot hide.
pub struct EngineCli {
    bin: &'static str,
    defs: Vec<ToolDef>,
    /// `None` is "this engine has not said", which is what selects [`RESERVED`].
    /// Distinct from `Some(vec![])`, which is "this engine has no management
    /// commands at all" and legitimately frees every name for a tool.
    management: Option<Vec<&'static str>>,
    /// The subject the tools operate on. `None` for a stateless engine.
    session: Option<&'static SessionSpec>,
    /// About text for `group.verb` group Commands. Empty means clap shows none.
    group_about: BTreeMap<String, String>,
}

impl EngineCli {
    pub fn new(bin: &'static str, defs: Vec<ToolDef>) -> Self {
        Self {
            bin,
            defs,
            management: None,
            session: None,
            group_about: BTreeMap::new(),
        }
    }

    /// Declare that this engine's tools operate on a session.
    ///
    /// Adds the spec's flags as globals on the tool subtree, and removes the
    /// schema property the spec names as its MCP-side selector — the CLI fills
    /// that slot itself, so publishing a flag for it as well would be offering
    /// two ways to say one thing with no rule about which wins.
    ///
    /// Panics if a declared flag would shadow one the schemas derive, for the
    /// same reason the tool-name check panics: clap resolves a duplicate long by
    /// keeping one and saying nothing.
    pub fn with_session(mut self, spec: &'static SessionSpec) -> Self {
        self.session = Some(spec);
        self
    }

    /// Name the root-level commands this engine handles itself.
    ///
    /// The declaration *replaces* [`RESERVED`] rather than adding to it. A union
    /// would keep half the bug the declaration exists to fix: a tool would still
    /// be refused a name no command of this engine occupies, and the only fixes
    /// for that false positive are `cli(none)` or a rename — and the rename
    /// changes the *MCP* tool name, because `group`/`verb` produce both.
    /// Freezing a guess into a published contract is the larger harm, and nothing
    /// is lost structurally: tools live under [`TOOL_COMMAND`], `help` is refused
    /// whatever is declared, and two tools resolving to one path is still a panic.
    pub fn with_management(mut self, names: &[&'static str]) -> Self {
        self.management = Some(names.to_vec());
        self
    }

    /// Set the about text shown for `group.verb` group Commands in `tool --help`.
    ///
    /// Clap group Commands have no tool description to inherit — the description
    /// lives on the leaf — so without this, `binary` / `annotation` render with
    /// an empty about. Replaces any previous map, matching [`Self::with_management`].
    pub fn with_group_about(mut self, about: &[(&str, &str)]) -> Self {
        self.group_about = about
            .iter()
            .map(|(group, text)| ((*group).to_owned(), (*text).to_owned()))
            .collect();
        self
    }

    /// Build the tree, panicking on any name clap would resolve by dropping a
    /// command.
    ///
    /// Tools sit under [`TOOL_COMMAND`] and `group.verb` names nest one level below
    /// that, so `binary.functions` is reachable as `<bin> tool binary functions`.
    /// The root is left to the engine's own management commands.
    pub fn command(self) -> Command {
        let Self {
            bin,
            defs,
            management,
            session,
            group_about,
        } = self;
        // Only a *declared* list describes commands that really get registered, so
        // only a declared list can be checked against the root clap owns. RESERVED
        // is a blocklist for tool names and contains `tool` and `help` by design.
        let declared = management.is_some();
        if let Some(names) = &management {
            reject_management_collisions(names);
        }
        let management = management.unwrap_or_else(|| RESERVED.to_vec());

        Command::new(bin)
            .subcommand_required(true)
            .arg_required_else_help(true)
            .subcommand(tool_tree(
                &defs,
                &management,
                declared,
                session,
                &group_about,
            ))
    }
}

impl From<EngineCli> for Command {
    fn from(cli: EngineCli) -> Self {
        cli.command()
    }
}

/// Build the whole command tree with the default management names.
///
/// Equivalent to `EngineCli::new(bin, defs).command()`; kept for callers that have
/// nothing to declare.
pub fn build(bin: &'static str, defs: &[ToolDef]) -> Command {
    EngineCli::new(bin, defs.to_vec()).command()
}

/// Names sitting at the root of a finished clap tree, minus [`TOOL_COMMAND`]
/// and clap's generated `help`.
///
/// Those two are not management commands: one is the derived tool subtree, the
/// other is clap's. What remains is what [`assert_management_matches_command`]
/// compares against the engine's `with_management` list — the check
/// `with_management` itself cannot do, because the engine grafts its Parser
/// tree *after* the kit has already consumed the declaration.
pub fn root_management_names(cmd: &Command) -> Vec<String> {
    let mut names: Vec<String> = cmd
        .get_subcommands()
        .map(|c| c.get_name().to_owned())
        .filter(|n| n != TOOL_COMMAND && n != "help")
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Panic if a finished clap tree's root commands disagree with `declared`.
///
/// Order-independent. [`TOOL_COMMAND`] and `help` are ignored on the clap side:
/// they are not management commands, and declaring them is already refused by
/// [`reject_management_collisions`]. Call this *after* the engine has grafted
/// its Parser tree onto the kit's `tool` subtree; `with_management` only feeds
/// the collision check, which runs too early to see those grafts.
pub fn assert_management_matches_command(cmd: &Command, declared: &[&str]) {
    let actual: BTreeSet<String> = root_management_names(cmd).into_iter().collect();
    let expected: BTreeSet<String> = declared.iter().copied().map(str::to_owned).collect();
    if actual == expected {
        return;
    }
    let extra_in_clap: Vec<String> = actual.difference(&expected).cloned().collect();
    let extra_in_declared: Vec<String> = expected.difference(&actual).cloned().collect();
    let mut detail = String::new();
    if !extra_in_clap.is_empty() {
        detail.push_str(&format!(" clap 有而声明没有: {extra_in_clap:?}；"));
    }
    if !extra_in_declared.is_empty() {
        detail.push_str(&format!(" 声明有而 clap 没有: {extra_in_declared:?}；"));
    }
    panic!(
        "管理命令声明与 clap 树不一致：`with_management` 声明 {declared:?}，\
         根子命令（不含 `{TOOL_COMMAND}` / `help`）为 {:?}。{detail}",
        actual.iter().cloned().collect::<Vec<_>>()
    );
}

/// Refuse a *management* name that clap itself already owns at the root.
///
/// Checkable only now that the engine says what it registers, and worth checking:
/// `.subcommand(Command::new("tool"))` would sit on top of the whole derived tool
/// tree, and clap would report neither.
fn reject_management_collisions(names: &[&str]) {
    for &name in names {
        if name == TOOL_COMMAND {
            panic!(
                "管理命令冲突：`{TOOL_COMMAND}` 是派生工具子树的根，\
                 引擎不能再用它作管理命令；clap 会静默丢掉其中一个"
            );
        }
        if name == "help" {
            panic!("管理命令冲突：`help` 由 clap 自动生成，引擎不能再注册同名管理命令");
        }
    }
}

fn tool_tree(
    defs: &[ToolDef],
    management: &[&str],
    declared: bool,
    session: Option<&'static SessionSpec>,
    group_about: &BTreeMap<String, String>,
) -> Command {
    let mut groups: BTreeMap<&str, Vec<&ToolDef>> = BTreeMap::new();
    let mut flat: Vec<&ToolDef> = Vec::new();
    for d in defs.iter().filter(|d| d.cli.enabled) {
        match d.name().split_once('.') {
            Some((g, _)) => groups.entry(g).or_default().push(d),
            None => flat.push(d),
        }
    }
    reject_collisions(&flat, &groups, management, declared);
    if let Some(spec) = session {
        reject_session_flag_collisions(spec, defs);
    }

    let mut root = Command::new(TOOL_COMMAND)
        .about("调用引擎工具（每个工具一个子命令）")
        .subcommand_required(true)
        .arg_required_else_help(true);
    if let Some(spec) = session {
        for arg in spec.args() {
            root = root.arg(arg);
        }
    }

    for d in flat {
        root = root.subcommand(subcommand(d, d.name(), session));
    }
    for (group, list) in groups {
        let mut gc = Command::new(group.to_owned())
            .subcommand_required(true)
            .arg_required_else_help(true);
        if let Some(about) = group_about.get(group) {
            gc = gc.about(about.clone());
        }
        for d in list {
            let leaf = verb_of(d);
            gc = gc.subcommand(subcommand(d, leaf, session));
        }
        root = root.subcommand(gc);
    }
    root
}

/// Refuse a session flag that a tool's own parameters already spell.
///
/// The session flags are `global(true)` on the tool subtree, so a leaf that
/// derives a `--idb` of its own would be defining the same long twice; clap
/// keeps one and reports nothing, and which one it keeps is not something the
/// engine chose. Same failure mode as the tool-name check, same treatment.
fn reject_session_flag_collisions(spec: &SessionSpec, defs: &[ToolDef]) {
    let reserved = spec.flags();
    for d in defs.iter().filter(|d| d.cli.enabled) {
        let root = d.tool.input_schema.as_ref();
        let Some(props) = properties(root) else {
            continue;
        };
        for name in props.keys() {
            if d.cli.positional.contains(&name.as_str()) {
                continue;
            }
            // Booleans also claim the hidden `--no-x` half of their pair.
            let derived = [kebab(name), format!("no-{}", kebab(name))];
            for flag in derived {
                if let Some(clash) = reserved.iter().find(|r| **r == flag) {
                    panic!(
                        "会话标志冲突：`--{clash}` 由 SessionSpec 声明，\
                         但工具 `{}` 的参数 `{name}` 也会派生出这个长选项；\
                         clap 会静默丢掉其中一个。请改 SessionSpec 的 flag 名。",
                        d.name()
                    );
                }
            }
        }
    }
}

fn verb_of(d: &ToolDef) -> &str {
    d.name().split_once('.').map(|(_, v)| v).unwrap_or(d.name())
}

/// Refuse any tool name clap would resolve by silently dropping a command.
///
/// Registering two subcommands under one name is not an error in clap; the later
/// one simply wins. The tree is built at process start, so a panic here shows up
/// on the engine's very first run — including in its own test suite — rather than
/// as a command that quietly stopped existing.
///
/// `management` is what the engine declared, or [`RESERVED`] when it declared
/// nothing; `declared` says which, so the message can point at the right fix.
fn reject_collisions<'a>(
    flat: &[&'a ToolDef],
    groups: &BTreeMap<&'a str, Vec<&'a ToolDef>>,
    management: &[&str],
    declared: bool,
) {
    // What sits directly under `tool`: a flat tool's whole name, or a group prefix.
    let mut heads: BTreeMap<&'a str, &'a str> = BTreeMap::new();
    let mut claim = |head: &'a str, owner: &'a str| {
        // Structural, and so independent of anything the engine declares: clap
        // generates a `help` subcommand at every level that has children, `tool`
        // included.
        if head == "help" {
            panic!(
                "工具名冲突：`{owner}` 会占用 clap 在 `{TOOL_COMMAND}` 下自动生成的 `help` 子命令"
            );
        }
        if management.contains(&head) {
            let source = if declared {
                "引擎声明的管理命令"
            } else {
                "默认保留名（该引擎未调用 with_management 声明自己的管理命令）"
            };
            panic!(
                "工具名冲突：工具 `{owner}` 会占用管理命令名 `{head}`，\
                 而该名字留给引擎的管理命令（<engine> {head}）。\
                 请改 group/verb，或给该工具标 cli(none)。{source}: {}",
                management.join(" / ")
            );
        }
        if let Some(prev) = heads.insert(head, owner) {
            panic!(
                "工具名冲突：`{prev}` 与 `{owner}` 都要占用 `tool {head}`；\
                 clap 会静默丢掉其中一个"
            );
        }
    };

    for &d in flat {
        claim(d.name(), d.name());
    }
    for (&group, list) in groups {
        claim(group, list[0].name());

        let mut verbs: BTreeMap<&'a str, &'a str> = BTreeMap::new();
        for &d in list {
            let verb = verb_of(d);
            // clap generates a `help` subcommand at every level that has children.
            if verb == "help" {
                panic!(
                    "工具名冲突：`{}` 会占用 clap 自动生成的 `help` 子命令",
                    d.name()
                );
            }
            if let Some(prev) = verbs.insert(verb, d.name()) {
                panic!(
                    "工具名冲突：`{prev}` 与 `{}` 都解析成 `tool {group} {verb}`",
                    d.name()
                );
            }
        }
    }
}

fn subcommand(d: &ToolDef, leaf: &str, session: Option<&'static SessionSpec>) -> Command {
    let root = d.tool.input_schema.as_ref();
    let mut cmd = Command::new(leaf.to_owned());
    if let Some(t) = &d.tool.title {
        cmd = cmd.about(t.clone());
    }
    if let Some(desc) = &d.tool.description {
        cmd = cmd.long_about(desc.to_string());
    }

    let required = required_names(root);
    // Parameters the CLI could not map at all, and parameters it mapped without
    // understanding. Both go in `after_help`; the second kind also carries the
    // caveat on its own flag, because `after_help` is below the fold and the
    // person typing `--address` is looking at the flag.
    let mut opaque: Vec<String> = Vec::new();
    let mut degraded: Vec<String> = Vec::new();

    if let Some(props) = properties(root) {
        let visible = mappable_properties(props, session);
        // Decide up front whether this subcommand needs the `--json-input` hatch:
        // if it does, required parameters must not be enforced on the flag path,
        // because the JSON file is allowed to supply them instead. A degraded
        // parameter needs it too — the hatch is the only way left to send the
        // array form its MCP surface accepts.
        let hatch = visible.values().any(|s| {
            let shape = classify(root, s);
            matches!(shape, Shape::Opaque) || shape.is_degraded()
        });
        for (name, schema) in registration_order(d, &visible) {
            let shape = classify(root, schema);
            if matches!(shape, Shape::Opaque) {
                opaque.push(name.clone());
                continue;
            }
            if shape.is_degraded() {
                degraded.push(name.clone());
            }
            let is_required = required.iter().any(|r| r == name);
            for a in arg_for(d, root, name, schema, &shape, is_required, hatch) {
                cmd = cmd.arg(a);
            }
        }
    }

    if !opaque.is_empty() || !degraded.is_empty() {
        let mut notes = Vec::new();
        if !opaque.is_empty() {
            notes.push(format!(
                "参数 {} 结构过于复杂，无法映射为命令行选项，请改用 --json-input",
                opaque.join(", ")
            ));
        }
        if !degraded.is_empty() {
            notes.push(format!(
                "参数 {} 的 schema 没有声明类型：命令行只能按单个字符串原样传递，不做任何校验；\
                 若该参数在 MCP 面接受数组，命令行给不了，请改用 --json-input",
                degraded.join(", ")
            ));
        }
        cmd = cmd
            .arg(
                Arg::new("__json_input")
                    .long("json-input")
                    .value_name("FILE")
                    .help("从文件读取完整 JSON 参数（'-' 表示 stdin）"),
            )
            .after_help(format!("注意：{}", notes.join("\n      ")));
    }

    cmd.arg(
        Arg::new("__json")
            .long("json")
            .action(ArgAction::SetTrue)
            .help("以 JSON 输出结果"),
    )
}

/// The schema properties this CLI is allowed to publish as arguments.
///
/// Drops the session selector: the CLI fills that slot from its own flag
/// ([`SessionSpec::flag`]), so a derived `--database` next to `--idb` would be
/// two spellings of one value with no rule about precedence.
fn mappable_properties(
    props: &Map<String, Value>,
    session: Option<&'static SessionSpec>,
) -> Map<String, Value> {
    let selector = session.and_then(|s| s.selector);
    props
        .iter()
        .filter(|(name, _)| Some(name.as_str()) != selector)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Parameters in the order their `Arg`s must be registered.
///
/// clap orders positionals by registration, and `properties` is a `serde_json`
/// map — alphabetical, because a plain `Map` is a `BTreeMap`. Iterating it
/// directly therefore sorted the positionals: `cli(positional = "start,end")` on
/// a tool taking a start and an end address produced `<END> <START>`, and
/// `tool find_paths 0xSTART 0xEND` swapped the two silently. For a directed
/// query that is a wrong answer, not an error, so nothing downstream could
/// catch it.
///
/// The hint is a declaration order, so honour it: hinted parameters first, in
/// the order they were written, then everything else. Flags are unaffected —
/// they are matched by name — so this only moves the positionals.
fn registration_order<'a>(
    d: &ToolDef,
    props: &'a Map<String, Value>,
) -> Vec<(&'a String, &'a Value)> {
    let mut ordered: Vec<(&String, &Value)> = Vec::with_capacity(props.len());
    for want in d.cli.positional {
        match props.get_key_value(*want) {
            Some(entry) => ordered.push(entry),
            // A hint naming a parameter no schema has is a typo that would
            // otherwise do nothing at all — the parameter stays a `--flag` and
            // the positional never appears.
            None => panic!(
                "CLI 提示有误：工具 `{}` 的 cli(positional) 里写了 `{want}`，\
                 但它的 inputSchema 没有这个参数；已有参数：{}",
                d.name(),
                props.keys().cloned().collect::<Vec<_>>().join(", ")
            ),
        }
    }
    ordered.extend(
        props
            .iter()
            .filter(|(name, _)| !d.cli.positional.contains(&name.as_str())),
    );
    ordered
}

fn properties(schema: &Map<String, Value>) -> Option<&Map<String, Value>> {
    schema.get("properties")?.as_object()
}

fn required_names(schema: &Map<String, Value>) -> Vec<&str> {
    schema
        .get("required")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

// `deref` / `effective` / `is_null_branch` / `types_of` all live in
// `crate::schema`: one vocabulary, read by this builder, by the contract scan and
// by the rewriting the tool macro applies — so what a client is offered and what
// this CLI describes cannot be different shapes.
//
// The null-branch handling below stays anyway, because `EngineCli::new` takes
// whatever `ToolDef`s it is handed. For a `#[vibrev_tool]` catalog it is inert;
// for a hand-built one it is the difference between a flag and a guess.

/// The permitted values of a parameter, or empty if it is not a closed set.
///
/// Four encodings, all of which schemars 1.2 emits depending on how the Rust
/// enum is written:
///
/// * `enum: [..]` — a plain unit-variant enum;
/// * `const: ".."` — one documented variant;
/// * `oneOf`/`anyOf` over those — and *mixed*, which is the one that is easy to
///   miss: schemars groups the undocumented variants into a single `enum`
///   branch and gives each documented one its own `const` branch, so an enum
///   where only some variants carry a doc comment is neither an all-`enum` nor
///   an all-`const` shape;
/// * any of the above behind a `$ref`, including the `anyOf: [{$ref}, {null}]`
///   that `Option<T>` produces.
///
/// A branch that yields nothing disqualifies the whole set — half a list of
/// permitted values would reject legitimate input, which is worse than not
/// validating at all.
fn enum_values(root: &Map<String, Value>, schema: &Value) -> Vec<String> {
    fn walk(root: &Map<String, Value>, schema: &Value, depth: u8) -> Option<Vec<String>> {
        if depth == 0 {
            return None;
        }
        let schema = deref(root, schema);
        if let Some(values) = schema.get("enum").and_then(Value::as_array) {
            let strings: Vec<String> = values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            return (strings.len() == values.len()).then_some(strings);
        }
        if let Some(one) = schema.get("const").and_then(Value::as_str) {
            return Some(vec![one.to_owned()]);
        }
        let branches = schema
            .get("oneOf")
            .or_else(|| schema.get("anyOf"))
            .and_then(Value::as_array)?;
        let mut out: Vec<String> = Vec::new();
        for b in branches {
            let b = deref(root, b);
            if is_null_branch(b) {
                continue;
            }
            for value in walk(root, b, depth - 1)? {
                if !out.contains(&value) {
                    out.push(value);
                }
            }
        }
        (!out.is_empty()).then_some(out)
    }

    walk(root, schema, 8).unwrap_or_default()
}

/// Rust field names arrive as snake_case; command lines are written in kebab-case.
/// Only the visible long flag is converted — the arg id stays the schema property
/// name, so mapping back to tool arguments needs no second lookup table.
///
/// Deliberately *not* applied to subcommand names, which is a real inconsistency
/// with a real reason: a flag is this crate's rendering of a field name, while a
/// subcommand **is** the tool name, and the tool name is a published contract.
/// `il.pseudo_c` is what `tools/call` takes and what [`resolve`] rebuilds from
/// the path, so spelling it `pseudo-c` on the command line would put a rename in
/// the middle of the one thing that has to stay single-sourced. An engine
/// that wants kebab-cased commands should name its tools that way and get both.
fn kebab(name: &str) -> String {
    name.replace('_', "-")
}

fn help_of(outer: &Value, inner: &Value) -> Option<String> {
    outer
        .get("description")
        .or_else(|| inner.get("description"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// The constructs this CLI knows how to carry on a command line.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Known {
    Bool,
    /// `minimum`/`maximum` travel with it: the schema states them on 90 of
    /// `ida-headless-mcp`'s parameters, so `--max-paths 9999` is refused here
    /// against a declared ceiling of 1024 instead of failing several seconds
    /// later inside the engine.
    Integer {
        min: Option<i64>,
        max: Option<i64>,
    },
    Number,
    Str,
    Enum(Vec<String>),
    Array(Box<Shape>),
}

/// What the mapper made of a parameter.
///
/// A **whitelist**: [`Known`] is the closed list of understood constructs and
/// everything else is one of the two honest failures. That direction is the
/// whole point. Asking "is this an object?" instead would be a question about
/// one construct the mapper happens to know it cannot carry — so a schema shaped
/// in any way it had never seen would answer "no" and be mapped as if
/// understood.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Shape {
    Known(Known),
    /// Understood, and genuinely uncarryable by a flag: a nested object. No arg
    /// is registered; `--json-input` is the only route.
    Opaque,
    /// Not understood. A flag is still registered — `--address 0x1000` is the
    /// common case and taking it away would buy no honesty — but it is a
    /// free-form, unvalidated, single string, and it says so on its own help
    /// line as well as in `after_help`.
    Unknown,
}

impl Shape {
    /// Mapped, but with less capability than the MCP surface has.
    fn is_degraded(&self) -> bool {
        match self {
            Self::Unknown => true,
            Self::Known(Known::Array(items)) => items.is_degraded(),
            _ => false,
        }
    }
}

/// The one caveat that has to be where the user is looking.
///
/// A parameter with no declared type is not merely unvalidated. 26 of
/// `ida-headless-mcp`'s describe themselves as "string/number **or array**", and
/// the MCP surface does accept the array — the derived flag cannot. That is a
/// real capability gap, not a display problem, and `--json-input` is an escape
/// hatch rather than parity. `after_help` alone is below the fold; this rides on
/// the flag itself.
const DEGRADED_NOTE: &str =
    "[未校验：schema 未声明类型，按单个字符串原样传递；若该参数接受数组，请改用 --json-input]";

fn push_note(help: &mut String, note: &str) {
    if !help.is_empty() {
        help.push(' ');
    }
    help.push_str(note);
}

fn range_note(min: Option<i64>, max: Option<i64>) -> Option<String> {
    match (min, max) {
        (Some(lo), Some(hi)) => Some(format!("[范围 {lo}..={hi}]")),
        (Some(lo), None) => Some(format!("[最小 {lo}]")),
        (None, Some(hi)) => Some(format!("[最大 {hi}]")),
        (None, None) => None,
    }
}

fn bound(schema: &Value, key: &str) -> Option<i64> {
    schema.get(key).and_then(Value::as_i64)
}

/// Recognise a parameter, or refuse to guess.
pub(crate) fn classify(root: &Map<String, Value>, schema: &Value) -> Shape {
    // Ask about the value set *before* collapsing: `effective` picks one branch
    // of an `anyOf`, which for an enum spread across several `const` branches
    // would keep the first variant and drop the rest — a shorter list of
    // permitted values that rejects legitimate input.
    let values = enum_values(root, schema);
    if !values.is_empty() {
        return Shape::Known(Known::Enum(values));
    }

    let inner = effective(root, schema);

    // `Option<T>` can arrive as `{"type": ["string", "null"]}`; the null branch
    // says nothing about how to spell a value.
    let types: Vec<&str> = types_of(inner)
        .into_iter()
        .filter(|t| *t != "null")
        .collect();
    let [single] = types.as_slice() else {
        // No type at all, or a union of several: either way nothing here says
        // how to parse the string the user typed.
        return Shape::Unknown;
    };

    match *single {
        "object" => Shape::Opaque,
        "boolean" => Shape::Known(Known::Bool),
        "integer" => Shape::Known(Known::Integer {
            min: bound(inner, "minimum"),
            max: bound(inner, "maximum"),
        }),
        "number" => Shape::Known(Known::Number),
        "string" => Shape::Known(Known::Str),
        "array" => {
            let items = inner.get("items").cloned().unwrap_or(Value::Null);
            let item_shape = match items {
                // `"items": true` and a missing `items` both mean "any value".
                Value::Null | Value::Bool(_) => Shape::Unknown,
                other => classify(root, &other),
            };
            // An array of objects cannot be spelled either.
            if matches!(item_shape, Shape::Opaque) {
                return Shape::Opaque;
            }
            Shape::Known(Known::Array(Box::new(item_shape)))
        }
        _ => Shape::Unknown,
    }
}

/// The `Arg`s for one parameter. Empty only for [`Shape::Opaque`], which the
/// caller routes to `--json-input` instead.
fn arg_for(
    d: &ToolDef,
    root: &Map<String, Value>,
    name: &str,
    schema: &Value,
    shape: &Shape,
    required: bool,
    hatch: bool,
) -> Vec<Arg> {
    let positional = d.cli.positional.contains(&name);
    let mut help = help_of(schema, effective(root, schema)).unwrap_or_default();
    match shape {
        Shape::Known(Known::Integer { min, max }) => {
            if let Some(note) = range_note(*min, *max) {
                push_note(&mut help, &note);
            }
        }
        s if s.is_degraded() => push_note(&mut help, DEGRADED_NOTE),
        _ => {}
    }

    // With a `--json-input` hatch present, "required" becomes "required unless the
    // JSON file provides it" — otherwise the escape hatch is unusable.
    let require = |a: Arg| match (required, hatch) {
        (false, _) => a,
        (true, false) => a.required(true),
        (true, true) => a.required_unless_present("__json_input"),
    };

    // Booleans get the `--x` / `--no-x` pair so an agent can override a true default.
    if matches!(shape, Shape::Known(Known::Bool)) && !positional {
        let yes = Arg::new(name.to_owned())
            .long(kebab(name))
            .action(ArgAction::SetTrue)
            .overrides_with(format!("no-{name}"))
            .help(help);
        let no = Arg::new(format!("no-{name}"))
            .long(format!("no-{}", kebab(name)))
            .action(ArgAction::SetTrue)
            .overrides_with(name.to_owned())
            .hide(true);
        return vec![yes, no];
    }

    let mut a = Arg::new(name.to_owned());
    if positional {
        a = require(a.value_name(name.to_uppercase()));
    } else {
        a = require(a.long(kebab(name)));
    }
    if !help.is_empty() {
        a = a.help(help);
    }
    if let Shape::Known(Known::Enum(values)) = shape {
        // Case-insensitively: the schema publishes one spelling, but an engine
        // whose handler lower-cased before matching accepts `--kind IMM` over
        // MCP, and a CLI that refused it would be stricter than the surface it
        // is derived from. The user's own casing is what reaches the tool, so
        // the engine still sees exactly what an MCP client would have sent.
        a = a
            .value_parser(clap::builder::PossibleValuesParser::new(values))
            .ignore_case(true);
    }
    if matches!(shape, Shape::Known(Known::Array(_))) {
        a = a.action(ArgAction::Append).num_args(1..);
    }
    vec![a]
}

/// Rebuild the tool's `arguments` object from parsed matches, coercing each value
/// to the type its schema declares.
///
/// A property with no registered `Arg` — the session selector, or an
/// [`Opaque`](Shape::Opaque) one — is skipped by construction: `try_get_one` on
/// an id clap never saw is an error, not a value.
pub fn to_arguments(d: &ToolDef, m: &ArgMatches) -> Result<Value, String> {
    let root = d.tool.input_schema.as_ref();
    let mut out = Map::new();
    let Some(props) = properties(root) else {
        return Ok(Value::Object(out));
    };

    for (name, schema) in props {
        let shape = classify(root, schema);

        if matches!(shape, Shape::Opaque) {
            continue; // handled by --json-input
        }

        if matches!(shape, Shape::Known(Known::Bool)) && !d.cli.positional.contains(&name.as_str())
        {
            let yes = m.try_get_one::<bool>(name).ok().flatten().copied() == Some(true);
            let no = m
                .try_get_one::<bool>(&format!("no-{name}"))
                .ok()
                .flatten()
                .copied()
                == Some(true);
            if yes {
                out.insert(name.clone(), Value::Bool(true));
            } else if no {
                out.insert(name.clone(), Value::Bool(false));
            }
            continue;
        }

        if let Shape::Known(Known::Array(items)) = &shape {
            let Some(values) = m.try_get_many::<String>(name).ok().flatten() else {
                continue;
            };
            let coerced: Result<Vec<Value>, String> =
                values.map(|v| coerce(v, items, d, name)).collect();
            out.insert(name.clone(), Value::Array(coerced?));
            continue;
        }

        let Some(raw) = m.try_get_one::<String>(name).ok().flatten() else {
            continue;
        };
        out.insert(name.clone(), coerce(raw, &shape, d, name)?);
    }

    Ok(Value::Object(out))
}

fn coerce(raw: &str, shape: &Shape, d: &ToolDef, name: &str) -> Result<Value, String> {
    let flag = kebab(name);
    match shape {
        Shape::Known(Known::Integer { min, max }) => {
            let n = parse_int(raw).map_err(|e| format!("--{flag}: {e}"))?;
            // clap's own `RangedI64ValueParser` cannot do this job: it parses
            // decimal only, and addresses in this domain are written `0x…`.
            if min.is_some_and(|lo| n < lo) || max.is_some_and(|hi| n > hi) {
                return Err(format!(
                    "--{flag}: {n} 超出 schema 声明的范围 {}",
                    range_note(*min, *max).unwrap_or_default()
                ));
            }
            Ok(Value::Number(n.into()))
        }
        Shape::Known(Known::Number) => {
            let n = parse_int(raw).map_err(|e| format!("--{flag}: {e}"))?;
            Ok(Value::Number(n.into()))
        }
        Shape::Known(Known::Bool) => match raw {
            "true" | "1" | "yes" => Ok(Value::Bool(true)),
            "false" | "0" | "no" => Ok(Value::Bool(false)),
            other => Err(format!("--{flag}: {other:?} is not a boolean")),
        },
        // An `int_args` hint is how a tool says "this untyped parameter is an
        // address": the schema does not say so, and without the hint the value
        // would ship as a string.
        _ if d.cli.int_args.contains(&name) => {
            let n = parse_int(raw).map_err(|e| format!("--{flag}: {e}"))?;
            Ok(Value::Number(n.into()))
        }
        _ => Ok(Value::String(raw.to_owned())),
    }
}

/// Resolve `ArgMatches` down to `(tool name, leaf matches)`.
///
/// Tools live under [`TOOL_COMMAND`], so the path is `tool <name>` or
/// `tool <group> <verb>`. Anything else at the root is one of the engine's own
/// management commands and yields `None` — the engine handles those itself.
pub fn resolve(m: &ArgMatches) -> Option<(String, &ArgMatches)> {
    let (root, tools) = m.subcommand()?;
    if root != TOOL_COMMAND {
        return None;
    }
    let (head, sub) = tools.subcommand()?;
    match sub.subcommand() {
        Some((leaf, leaf_m)) => Some((format!("{head}.{leaf}"), leaf_m)),
        None => Some((head.to_owned(), sub)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CliHints;

    fn def(name: &'static str) -> ToolDef {
        let schema: Map<String, Value> = serde_json::from_value(serde_json::json!({
            "type": "object",
            "properties": { "limit": { "type": "integer" } },
        }))
        .expect("an object schema is an object");
        ToolDef {
            tool: rmcp::model::Tool::new(name, "test tool", schema),
            cli: CliHints {
                positional: &[],
                int_args: &[],
                enabled: true,
                needs_session: true,
            },
            ext: None,
        }
    }

    /// The engine's own commands, added the way `toy-engine` adds `mcp`: declared
    /// to the kit, then registered on the root it hands back.
    fn engine(defs: &[ToolDef]) -> Command {
        EngineCli::new("eng", defs.to_vec())
            .with_management(&["mcp", "status"])
            .command()
            .subcommand(Command::new("mcp"))
            .subcommand(Command::new("status"))
    }

    #[test]
    fn tools_hang_off_tool_and_leave_the_root_to_management_commands() {
        let cmd = engine(&[def("decompile"), def("binary.functions")]);
        let roots: Vec<&str> = cmd
            .get_subcommands()
            .map(|c| c.get_name())
            .filter(|n| *n != "help")
            .collect();
        assert_eq!(roots, [TOOL_COMMAND, "mcp", "status"]);

        let tools: Vec<&str> = cmd
            .find_subcommand(TOOL_COMMAND)
            .expect("the tool subcommand exists")
            .get_subcommands()
            .map(|c| c.get_name())
            .filter(|n| *n != "help")
            .collect();
        assert_eq!(tools, ["decompile", "binary"]);
    }

    #[test]
    fn resolve_strips_the_tool_level_and_still_follows_group_verb() {
        let defs = [def("decompile"), def("binary.functions")];

        let m = engine(&defs).get_matches_from(["eng", "tool", "decompile", "--limit", "20"]);
        let (name, leaf) = resolve(&m).expect("a tool path resolves");
        assert_eq!(name, "decompile");
        assert_eq!(
            leaf.get_one::<String>("limit").map(String::as_str),
            Some("20")
        );

        let m = engine(&defs).get_matches_from(["eng", "tool", "binary", "functions"]);
        assert_eq!(
            resolve(&m).expect("a group path resolves").0,
            "binary.functions"
        );
    }

    /// The whole point of the `tool` level: a management command still reaches the
    /// engine even when a tool would otherwise have been named the same thing.
    #[test]
    fn a_management_command_resolves_to_no_tool_at_all() {
        let m = engine(&[def("decompile")]).get_matches_from(["eng", "mcp"]);
        assert_eq!(m.subcommand_name(), Some("mcp"));
        assert!(resolve(&m).is_none());
    }

    /// Backward compatibility: an engine that declares nothing is checked against
    /// [`RESERVED`].
    #[test]
    #[should_panic(expected = "管理命令名 `status`")]
    fn an_undeclared_engine_still_falls_back_to_the_reserved_list() {
        let _ = build("eng", &[def("status")]);
    }

    /// …and the message says the list was a default, so the fix (declare) is
    /// visible from the panic alone.
    #[test]
    #[should_panic(expected = "未调用 with_management")]
    fn the_fallback_says_it_is_a_fallback() {
        let _ = build("eng", &[def("serve")]);
    }

    /// The case `RESERVED` could not have caught: rjadx really does have a
    /// `decompile` management command, and `decompile` is nowhere in the guess.
    #[test]
    #[should_panic(expected = "管理命令名 `decompile`")]
    fn a_tool_may_not_claim_a_name_the_engine_declared() {
        let _ = EngineCli::new("eng", vec![def("decompile")])
            .with_management(&["mcp", "decompile"])
            .command();
    }

    /// A group prefix claims the same slot under `tool` that a flat tool does, so
    /// it is checked against the declaration too.
    #[test]
    #[should_panic(expected = "管理命令名 `decompile`")]
    fn a_group_prefix_may_not_claim_a_declared_name_either() {
        let _ = EngineCli::new("eng", vec![def("decompile.java")])
            .with_management(&["decompile"])
            .command();
    }

    /// The declaration replaces the guess: an engine with no `status` command may
    /// name a tool `status`, and its MCP name survives the CLI's opinion.
    #[test]
    fn a_declaration_frees_the_names_the_guess_had_reserved() {
        let cmd = EngineCli::new("eng", vec![def("status"), def("serve")])
            .with_management(&["mcp"])
            .command();
        let tools: Vec<&str> = cmd
            .find_subcommand(TOOL_COMMAND)
            .expect("the tool subcommand exists")
            .get_subcommands()
            .map(|c| c.get_name())
            .filter(|n| *n != "help")
            .collect();
        assert_eq!(tools, ["status", "serve"]);
    }

    /// `help` is clap's, at every level with children — no declaration can hand it
    /// to a tool.
    #[test]
    #[should_panic(expected = "自动生成的 `help` 子命令")]
    fn help_is_refused_whatever_the_engine_declares() {
        let _ = EngineCli::new("eng", vec![def("help")])
            .with_management(&["mcp"])
            .command();
    }

    /// The check the declaration makes possible in the other direction: a
    /// management command that would sit on top of the tool tree itself.
    #[test]
    #[should_panic(expected = "`tool` 是派生工具子树的根")]
    fn an_engine_may_not_declare_a_management_command_called_tool() {
        let _ = EngineCli::new("eng", vec![def("decompile")])
            .with_management(&["mcp", "tool"])
            .command();
    }

    fn finished_root(names: &[&str]) -> Command {
        let mut cmd = Command::new("eng").subcommand(Command::new(TOOL_COMMAND));
        for name in names {
            cmd = cmd.subcommand(Command::new((*name).to_owned()));
        }
        cmd
    }

    #[test]
    fn a_matching_management_declaration_passes() {
        assert_management_matches_command(&finished_root(&["status", "mcp"]), &["mcp", "status"]);
    }

    #[test]
    #[should_panic(expected = "clap 有而声明没有: [\"probe\"]")]
    fn an_extra_clap_subcommand_is_drift() {
        assert_management_matches_command(&finished_root(&["mcp", "probe"]), &["mcp"]);
    }

    #[test]
    #[should_panic(expected = "声明有而 clap 没有: [\"status\"]")]
    fn an_extra_declared_name_is_drift() {
        assert_management_matches_command(&finished_root(&["mcp"]), &["mcp", "status"]);
    }

    #[test]
    fn help_and_tool_on_the_clap_tree_are_not_management_commands() {
        let cmd = Command::new("eng")
            .subcommand(Command::new("mcp"))
            .subcommand(Command::new(TOOL_COMMAND))
            .subcommand(Command::new("help"));
        assert_management_matches_command(&cmd, &["mcp"]);
        assert_eq!(root_management_names(&cmd), ["mcp"]);
    }

    #[test]
    fn a_group_about_shows_in_help_and_an_unmentioned_group_stays_empty() {
        let cmd = EngineCli::new(
            "eng",
            vec![def("binary.functions"), def("annotation.rename")],
        )
        .with_management(&["mcp"])
        .with_group_about(&[("binary", "Inspect the mapped image")])
        .command();
        let mut tools = cmd
            .find_subcommand(TOOL_COMMAND)
            .expect("the tool subcommand exists")
            .clone();
        let help = tools.render_help().to_string();
        assert!(
            help.contains("Inspect the mapped image"),
            "group_about must appear in `tool --help`: {help}"
        );
        assert_eq!(
            tools
                .find_subcommand("binary")
                .expect("binary")
                .get_about()
                .map(ToString::to_string)
                .as_deref(),
            Some("Inspect the mapped image")
        );
        assert!(
            tools
                .find_subcommand("annotation")
                .expect("annotation")
                .get_about()
                .is_none(),
            "a group without group_about must stay empty"
        );
    }

    #[test]
    #[should_panic(expected = "都要占用 `tool binary`")]
    fn a_flat_tool_may_not_shadow_a_group_of_the_same_name() {
        let _ = build("eng", &[def("binary"), def("binary.functions")]);
    }

    fn two_positionals(positional: &'static [&'static str]) -> ToolDef {
        let schema: Map<String, Value> = serde_json::from_value(serde_json::json!({
            "type": "object",
            // Written end-first so alphabetical order and declaration order
            // disagree in *both* directions — sorting cannot pass by luck.
            "properties": { "start": { "type": "string" }, "end": { "type": "string" } },
            "required": ["start", "end"],
        }))
        .expect("an object schema is an object");
        ToolDef {
            tool: rmcp::model::Tool::new("find_paths", "paths from start to end", schema),
            cli: CliHints {
                positional,
                int_args: &[],
                enabled: true,
                needs_session: true,
            },
            ext: None,
        }
    }

    fn positionals_of(cmd: &Command) -> Vec<&str> {
        cmd.find_subcommand(TOOL_COMMAND)
            .expect("the tool subcommand exists")
            .find_subcommand("find_paths")
            .expect("the tool is registered")
            .get_positionals()
            .map(|a| a.get_id().as_str())
            .collect()
    }

    /// `properties` is alphabetical and clap orders positionals by registration,
    /// so iterating the schema put `<END>` before `<START>` and quietly swapped
    /// the two addresses of a directed query.
    #[test]
    fn positionals_follow_the_hint_not_the_alphabet() {
        let cmd = EngineCli::new("eng", vec![two_positionals(&["start", "end"])])
            .with_management(&["mcp"])
            .command();
        assert_eq!(positionals_of(&cmd), ["start", "end"]);
    }

    /// …and the hint really is what decides, rather than some other order that
    /// happens to agree with it.
    #[test]
    fn reversing_the_hint_reverses_the_positionals() {
        let cmd = EngineCli::new("eng", vec![two_positionals(&["end", "start"])])
            .with_management(&["mcp"])
            .command();
        assert_eq!(positionals_of(&cmd), ["end", "start"]);
    }

    /// End to end: the swap showed up in the *arguments*, which is where it did
    /// the damage.
    #[test]
    fn a_two_address_query_keeps_its_direction() {
        let d = two_positionals(&["start", "end"]);
        let m = EngineCli::new("eng", vec![d.clone()])
            .with_management(&["mcp"])
            .command()
            .get_matches_from(["eng", "tool", "find_paths", "0x1000", "0x2000"]);
        let (_, leaf) = resolve(&m).expect("a tool path resolves");
        let args = to_arguments(&d, leaf).expect("both positionals map");
        assert_eq!(args["start"], "0x1000");
        assert_eq!(args["end"], "0x2000");
    }

    /// A hint that names nothing is a typo whose only symptom would be a missing
    /// positional, so it fails at tree-build time like every other name mistake.
    #[test]
    #[should_panic(expected = "cli(positional) 里写了 `strat`")]
    fn a_positional_hint_must_name_a_real_parameter() {
        let _ = EngineCli::new("eng", vec![two_positionals(&["strat"])])
            .with_management(&["mcp"])
            .command();
    }

    // -----------------------------------------------------------------------
    // The whitelist
    // -----------------------------------------------------------------------

    fn tool(name: &'static str, schema: Value) -> ToolDef {
        tool_with_hints(name, schema, &[], &[])
    }

    fn tool_with_hints(
        name: &'static str,
        schema: Value,
        positional: &'static [&'static str],
        int_args: &'static [&'static str],
    ) -> ToolDef {
        let schema: Map<String, Value> =
            serde_json::from_value(schema).expect("an object schema is an object");
        ToolDef {
            tool: rmcp::model::Tool::new(name, "test tool", schema),
            cli: CliHints {
                positional,
                int_args,
                enabled: true,
                needs_session: true,
            },
            ext: None,
        }
    }

    fn shape_of(schema: Value) -> Shape {
        let root: Map<String, Value> = serde_json::from_value(serde_json::json!({
            "type": "object",
            "properties": { "p": schema },
            "$defs": {
                "Scope": { "enum": ["auto", "func", "line"] },
                "ScopeAlias": { "$ref": "#/$defs/Scope" },
                "Deep": { "$ref": "#/$defs/ScopeAlias" },
                // Copied out of a real `tools/list`: schemars 1.2 gives every
                // documented variant its own `const` branch, with a `type`.
                "DocumentedScope": { "oneOf": [
                    {"const": "auto", "description": "…", "type": "string"},
                    {"const": "func", "description": "…", "type": "string"},
                    {"const": "line", "description": "…", "type": "string"},
                ]},
                // …and folds the undocumented ones into a single `enum` branch.
                "MixedKind": { "oneOf": [
                    {"enum": ["text", "imm"], "type": "string"},
                    {"const": "auto", "description": "…", "type": "string"},
                ]},
            },
        }))
        .expect("an object schema is an object");
        let props = properties(&root).expect("properties exist").clone();
        classify(&root, &props["p"])
    }

    /// The measured `ida-headless-mcp` cases, which would otherwise reach the
    /// generic tail and become indistinguishable from a real `type: "string"`
    /// parameter.
    #[test]
    fn a_schema_that_declares_no_type_is_not_understood() {
        // C-1: `serde_json::Value` with a description, 46 parameters.
        assert_eq!(
            shape_of(serde_json::json!({"description": "Address(es) (string/number or array)"})),
            Shape::Unknown
        );
        // C-2: the boolean schema `true`, 6 parameters on `sdk_mutation`.
        assert_eq!(shape_of(serde_json::json!(true)), Shape::Unknown);
        // A union says how to spell neither branch.
        assert_eq!(
            shape_of(serde_json::json!({"type": ["string", "integer"]})),
            Shape::Unknown
        );
        // A type nobody here has implemented is *not* silently a string.
        assert_eq!(
            shape_of(serde_json::json!({"type": "geometry"})),
            Shape::Unknown
        );
    }

    #[test]
    fn the_understood_constructs_are_recognised_as_themselves() {
        assert_eq!(
            shape_of(serde_json::json!({"type": "string"})),
            Shape::Known(Known::Str)
        );
        assert_eq!(
            shape_of(serde_json::json!({"type": "boolean"})),
            Shape::Known(Known::Bool)
        );
        // `Option<T>` arrives with a null branch on the type list; it says
        // nothing about how to spell a value, so it is stripped rather than
        // making the parameter a union.
        assert_eq!(
            shape_of(serde_json::json!({"type": ["string", "null"]})),
            Shape::Known(Known::Str)
        );
        assert_eq!(
            shape_of(serde_json::json!({"type": "integer", "minimum": 1, "maximum": 1024})),
            Shape::Known(Known::Integer {
                min: Some(1),
                max: Some(1024)
            })
        );
        assert_eq!(
            shape_of(serde_json::json!({"type": "array", "items": {"type": "string"}})),
            Shape::Known(Known::Array(Box::new(Shape::Known(Known::Str))))
        );
        // C-3: `items: true` is "any value", so the array maps but its elements
        // are not understood — which is what makes the parameter degraded.
        let items_any = shape_of(serde_json::json!({"type": "array", "items": true}));
        assert_eq!(
            items_any,
            Shape::Known(Known::Array(Box::new(Shape::Unknown)))
        );
        assert!(items_any.is_degraded());
    }

    #[test]
    fn an_object_is_uncarryable_rather_than_merely_unknown() {
        assert_eq!(
            shape_of(serde_json::json!({"type": "object", "properties": {}})),
            Shape::Opaque
        );
        // …and so is an array of them: `--x '{"a":1}'` is not a spelling.
        assert_eq!(
            shape_of(serde_json::json!({"type": "array", "items": {"type": "object"}})),
            Shape::Opaque
        );
    }

    // -----------------------------------------------------------------------
    // Constructs IDA never produces. JADX and Binary Ninja will, so these are
    // exercised with hand-built schemas rather than left to a future bug report.
    // -----------------------------------------------------------------------

    #[test]
    fn a_ref_into_defs_resolves_to_what_it_names() {
        assert_eq!(
            shape_of(serde_json::json!({"$ref": "#/$defs/Scope"})),
            Shape::Known(Known::Enum(vec![
                "auto".to_owned(),
                "func".to_owned(),
                "line".to_owned()
            ]))
        );
    }

    /// A `$defs` entry that is itself a `$ref` — a newtype over an enum. The
    /// single-hop version returned the inner `$ref` object, which has no `type`
    /// and no `enum`, so the enum degraded to a free-form string.
    #[test]
    fn a_chain_of_refs_is_followed_to_the_end() {
        assert_eq!(
            shape_of(serde_json::json!({"$ref": "#/$defs/Deep"})),
            Shape::Known(Known::Enum(vec![
                "auto".to_owned(),
                "func".to_owned(),
                "line".to_owned()
            ]))
        );
    }

    /// A dangling `$ref` is not understood — not silently a string.
    #[test]
    fn a_ref_that_names_nothing_is_unknown() {
        assert_eq!(
            shape_of(serde_json::json!({"$ref": "#/$defs/Missing"})),
            Shape::Unknown
        );
    }

    #[test]
    fn an_any_of_with_a_null_branch_collapses_to_the_value_branch() {
        assert_eq!(
            shape_of(serde_json::json!({
                "anyOf": [{"type": "null"}, {"type": "integer", "maximum": 10}]
            })),
            Shape::Known(Known::Integer {
                min: None,
                max: Some(10)
            })
        );
    }

    /// The shape schemars 1.2 emits for `Option<SomeEnum>`, verbatim from
    /// `ida-headless-mcp`'s `comment_append`.
    ///
    /// Two separate bugs met here and the parameter came out an unvalidated
    /// string. The null test was "no non-null type", vacuously true of the
    /// `$ref` branch, so the *value* branch was mistaken for the null one and
    /// skipped; and even reached, `oneOf` of `const`s was only recognised when
    /// every branch was a `const`.
    #[test]
    fn an_optional_enum_behind_a_ref_keeps_all_its_variants() {
        let shape = shape_of(serde_json::json!({
            "anyOf": [{"$ref": "#/$defs/DocumentedScope"}, {"type": "null"}],
            "description": "Comment scope: auto (default), func, or line",
        }));
        assert_eq!(
            shape,
            Shape::Known(Known::Enum(vec![
                "auto".to_owned(),
                "func".to_owned(),
                "line".to_owned()
            ]))
        );
    }

    /// schemars groups the *undocumented* variants of an enum into one `enum`
    /// branch and gives each documented one its own `const` branch. An enum
    /// where only some variants carry a doc comment is therefore neither shape,
    /// and the all-`const` check dropped the whole set.
    #[test]
    fn a_one_of_that_mixes_enum_and_const_branches_is_still_an_enum() {
        let shape = shape_of(serde_json::json!({"$ref": "#/$defs/MixedKind"}));
        assert_eq!(
            shape,
            Shape::Known(Known::Enum(vec![
                "text".to_owned(),
                "imm".to_owned(),
                "auto".to_owned()
            ]))
        );
    }

    /// A branch nobody understood must not shorten the list: half a set of
    /// permitted values rejects legitimate input, which is worse than not
    /// validating.
    #[test]
    fn an_unreadable_branch_disqualifies_the_whole_value_set() {
        assert_eq!(
            shape_of(serde_json::json!({
                "oneOf": [{"const": "text"}, {"type": "string", "pattern": "^x"}]
            })),
            Shape::Unknown
        );
    }

    #[test]
    fn a_one_of_of_consts_is_an_enum() {
        let cmd = EngineCli::new(
            "eng",
            vec![tool(
                "search",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "kind": {"oneOf": [{"const": "text"}, {"const": "imm"}]}
                    },
                }),
            )],
        )
        .with_management(&["mcp"])
        .command();
        let arg = cmd
            .find_subcommand(TOOL_COMMAND)
            .and_then(|c| c.find_subcommand("search"))
            .and_then(|c| c.get_arguments().find(|a| a.get_id() == "kind"))
            .expect("the enum parameter is registered")
            .clone();
        let values: Vec<String> = arg
            .get_possible_values()
            .iter()
            .map(|v| v.get_name().to_owned())
            .collect();
        assert_eq!(values, ["text", "imm"]);
    }

    // -----------------------------------------------------------------------
    // Visible degradation
    // -----------------------------------------------------------------------

    fn leaf<'a>(cmd: &'a Command, name: &str) -> &'a Command {
        cmd.find_subcommand(TOOL_COMMAND)
            .expect("the tool subtree exists")
            .find_subcommand(name)
            .expect("the tool is registered")
    }

    fn untyped_tool() -> ToolDef {
        tool(
            "decompile",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "address": {"description": "Address(es) (string/number or array)"}
                },
                "required": ["address"],
            }),
        )
    }

    /// The flag survives — `decompile 0x1000` is the common case — but it now
    /// says what it lost, on its own help line rather than only in `after_help`,
    /// which is below the fold.
    #[test]
    fn an_untyped_parameter_keeps_its_flag_and_admits_what_it_cannot_do() {
        let cmd = EngineCli::new("eng", vec![untyped_tool()])
            .with_management(&["mcp"])
            .command();
        let sub = leaf(&cmd, "decompile");

        let help = sub
            .get_arguments()
            .find(|a| a.get_id() == "address")
            .and_then(|a| a.get_help().map(ToString::to_string))
            .expect("the flag is registered and has help");
        assert!(help.contains("Address(es)"), "{help}");
        assert!(help.contains("未校验"), "{help}");
        assert!(help.contains("--json-input"), "{help}");

        // And the escape hatch really is there, so the note is actionable.
        assert!(sub.get_arguments().any(|a| a.get_id() == "__json_input"));
        let after = sub
            .get_after_help()
            .map(ToString::to_string)
            .unwrap_or_default();
        assert!(after.contains("address"), "{after}");
    }

    /// A tool whose parameters are all understood grows no hatch and no note —
    /// otherwise the warning would be noise and stop being read.
    #[test]
    fn a_fully_understood_tool_says_nothing_extra() {
        let sub_owner = EngineCli::new("eng", vec![def("list_functions")])
            .with_management(&["mcp"])
            .command();
        let sub = leaf(&sub_owner, "list_functions");
        assert!(!sub.get_arguments().any(|a| a.get_id() == "__json_input"));
        assert_eq!(sub.get_after_help().map(ToString::to_string), None);
    }

    // -----------------------------------------------------------------------
    // minimum / maximum
    // -----------------------------------------------------------------------

    fn bounded() -> ToolDef {
        tool(
            "find_paths",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "max_paths": {
                        "type": "integer", "minimum": 1, "maximum": 1024,
                        "description": "Maximum paths to return (default: 8)"
                    }
                },
            }),
        )
    }

    #[test]
    fn declared_bounds_reach_both_the_help_and_the_check() {
        let d = bounded();
        let cmd = EngineCli::new("eng", vec![d.clone()])
            .with_management(&["mcp"])
            .command();
        let help = leaf(&cmd, "find_paths")
            .get_arguments()
            .find(|a| a.get_id() == "max_paths")
            .and_then(|a| a.get_help().map(ToString::to_string))
            .expect("the flag has help");
        assert!(help.contains("1..=1024"), "{help}");

        let ok = EngineCli::new("eng", vec![d.clone()])
            .with_management(&["mcp"])
            .command()
            .get_matches_from(["eng", "tool", "find_paths", "--max-paths", "0x20"]);
        let (_, m) = resolve(&ok).expect("a tool path resolves");
        assert_eq!(to_arguments(&d, m).expect("in range")["max_paths"], 32);

        let over = EngineCli::new("eng", vec![d.clone()])
            .with_management(&["mcp"])
            .command()
            .get_matches_from(["eng", "tool", "find_paths", "--max-paths", "9999"]);
        let (_, m) = resolve(&over).expect("a tool path resolves");
        let error = to_arguments(&d, m).expect_err("9999 is past the declared ceiling");
        assert!(error.contains("9999"), "{error}");
        assert!(error.contains("1024"), "{error}");
    }

    // -----------------------------------------------------------------------
    // The session slot
    // -----------------------------------------------------------------------

    const IDB: crate::session::SessionSpec = crate::session::SessionSpec {
        selector: Some("database"),
        flag: "idb",
        value_name: "PATH",
        help: "要打开的数据库",
        missing: "工具都读当前打开的数据库",
        ready: Some(crate::session::ReadySpec {
            skip_flag: "no-wait-analysis",
            skip_help: "跳过等待",
            timeout: std::time::Duration::from_secs(1),
            poll: std::time::Duration::from_millis(10),
            timed_out: "超时",
            unknown: "说不准",
        }),
    };

    fn selector_tool() -> ToolDef {
        tool(
            "segments",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "database": {"type": "string", "description": "Session ID"},
                    "limit": {"type": "integer"},
                },
                "required": ["database"],
            }),
        )
    }

    /// The selector is filled by the CLI's own flag, so publishing a `--database`
    /// beside `--idb` would be two spellings of one value with no precedence
    /// rule. It disappears by derivation rather than by an engine remembering to
    /// strip it.
    #[test]
    fn the_session_selector_becomes_no_flag_and_is_never_sent() {
        let d = selector_tool();
        let cmd = EngineCli::new("eng", vec![d.clone()])
            .with_management(&["mcp"])
            .with_session(&IDB)
            .command();

        let sub = leaf(&cmd, "segments");
        assert!(
            !sub.get_arguments().any(|a| a.get_id() == "database"),
            "the selector must not become a flag"
        );

        let m = EngineCli::new("eng", vec![d.clone()])
            .with_management(&["mcp"])
            .with_session(&IDB)
            .command()
            .get_matches_from([
                "eng", "tool", "--idb", "/tmp/cat", "segments", "--limit", "5",
            ]);
        let (_, leaf_m) = resolve(&m).expect("a tool path resolves");
        let args = to_arguments(&d, leaf_m).expect("the mapped parameters coerce");
        assert_eq!(args["limit"], 5);
        assert!(
            args.get("database").is_none(),
            "the selector leaked into the tool arguments: {args}"
        );
        assert_eq!(
            IDB.read(leaf_m).expect("--idb was given").target,
            "/tmp/cat"
        );
    }

    /// An engine that declares no session keeps the property as an ordinary
    /// flag — nothing here is done behind an engine's back.
    #[test]
    fn without_a_session_declaration_the_property_is_just_a_parameter() {
        let cmd = EngineCli::new("eng", vec![selector_tool()])
            .with_management(&["mcp"])
            .command();
        assert!(
            leaf(&cmd, "segments")
                .get_arguments()
                .any(|a| a.get_id() == "database")
        );
    }

    #[test]
    #[should_panic(expected = "会话标志冲突：`--idb`")]
    fn a_tool_parameter_may_not_shadow_the_session_flag() {
        let _ = EngineCli::new(
            "eng",
            vec![tool(
                "open",
                serde_json::json!({
                    "type": "object",
                    "properties": { "idb": {"type": "string"} },
                }),
            )],
        )
        .with_management(&["mcp"])
        .with_session(&IDB)
        .command();
    }

    /// The hidden `--no-x` half of a boolean pair claims a long too, so it is
    /// checked as well.
    #[test]
    #[should_panic(expected = "会话标志冲突：`--no-wait-analysis`")]
    fn the_hidden_half_of_a_boolean_pair_is_checked_too() {
        let _ = EngineCli::new(
            "eng",
            vec![tool(
                "analyze",
                serde_json::json!({
                    "type": "object",
                    "properties": { "wait_analysis": {"type": "boolean"} },
                }),
            )],
        )
        .with_management(&["mcp"])
        .with_session(&IDB)
        .command();
    }
}
