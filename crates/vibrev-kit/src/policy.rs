//! Which tools an engine offers, when a user has asked for fewer.
//!
//! Every engine needs this and only one has it. `ida-headless-mcp` carries two
//! near-identical copies (`server/tool_filter.rs` and
//! `supervisor/tool_filter.rs`, 310 non-test lines of which ~90% is mechanism);
//! `bn-headless-mcp` has none at all, so there was no way to start it read-only
//! even though nineteen of its forty-seven tools patch bytes, edit types, or run
//! Python.
//!
//! # Everything is on until someone turns something off
//!
//! There is no gate here that hides a tool by default. An engine that ships a
//! tool ships it; a policy exists to honour a *user's* request for less, not to
//! second-guess one they did not make. A capability withheld by default is a
//! capability the operator has to discover a flag to get back, and the discovery
//! path is usually "why does this not work".
//!
//! So the flags only ever subtract, and a fresh [`ToolPolicy`] built from no
//! input at all admits the whole catalog.
//!
//! # The composition order is a contract
//!
//! The four inputs compose in a fixed order, and the order is the whole
//! semantics — it is what makes `--exclude-tools` mean something definite when
//! it disagrees with `--tools`:
//!
//! 1. No include given → start from the whole catalog. Any include given → start
//!    from nothing. So naming one toolset narrows, rather than adding to "all".
//! 2. Union in the named categories, then the named tools, then whatever the
//!    engine declared [essential](PolicyBuilder::essential) — the tools without
//!    which the rest cannot be reached at all.
//! 3. Subtract the excluded tools. **Exclusion always wins over inclusion**, and
//!    reaches the essential ones too: picking a category is a guess about what
//!    you need, naming a tool is a statement.
//! 4. Subtract the writers if read-only was asked for, essential ones excepted.
//!
//! An empty final set is an error rather than a server that advertises nothing:
//! a client cannot tell "this engine has no tools" from "your flags cancelled
//! out", and only one of those is worth restarting over. "Empty" here means
//! nothing left that does work — a selection that left only the session
//! primitives left a server that can open a view and then do nothing with it,
//! which is the same dead end reached by a different road.
//!
//! # Read-only reads the annotation, it does not keep a list
//!
//! A tool is a writer when its `readOnlyHint` is not `true`. `#[vibrev_tool]`
//! refuses to expand without `annotations(read_only = ..)` and
//! [`contract`](crate::contract) fails a surface where the hint is absent, so
//! the annotation is always there to read — which means a new mutating tool is
//! denied the day it lands, with no second list anyone can forget.
//!
//! Treating an absent hint as mutating is deliberate. It is the one place this
//! module errs towards less, because the alternative is a write tool surviving
//! an explicit `--read-only` through an omission nobody noticed.
//!
//! # What is here and what is not
//!
//! The mechanism is here; the taxonomy is the engine's. IDA has twelve hand-kept
//! `ToolCategory` variants, and BN's `group.verb` names are already a taxonomy
//! that nobody has to write down — see [`Taxonomy::by_dot_prefix`]. Same split
//! as [`contract`](crate::contract): the moment kit holds a list of one engine's
//! tool names it has stopped being shared.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use clap::{Arg, ArgAction, ArgMatches};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, ListToolsResult, PaginatedRequestParams, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler};

use crate::Advertised;
use crate::decorate::Decorator;

/// A selection that cannot be satisfied.
///
/// Hand-written rather than `thiserror`: this crate is a path dependency of
/// every engine, so each entry in its dependency graph is one every engine
/// carries. Three variants and a `Display` impl are not worth that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// A category name nobody registered. Carries the known names, because the
    /// useful thing to print next is the list the user meant to pick from.
    UnknownCategory { name: String, known: Vec<String> },
    /// A tool name that is not on this surface.
    UnknownTool(String),
    /// The inputs cancelled out.
    Empty,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::UnknownCategory { name, known } => write!(
                f,
                "unknown tool category {name:?}; this engine has {}",
                known.join(", ")
            ),
            PolicyError::UnknownTool(name) => write!(f, "unknown tool {name:?}"),
            PolicyError::Empty => f.write_str(
                "the tool selection is empty; an exclusion or --read-only removed \
                 everything the includes selected",
            ),
        }
    }
}

impl std::error::Error for PolicyError {}

/// The engine's answer to "which tools go together".
///
/// Built by the engine and handed in. Two ways to build one: register each tool
/// against a category, or let [`by_dot_prefix`](Self::by_dot_prefix) read the
/// `group.verb` naming an engine already uses.
#[derive(Debug, Clone, Default)]
pub struct Taxonomy {
    members: BTreeMap<String, BTreeSet<String>>,
    /// What a user may type instead of the canonical name, for either a category
    /// or a tool. IDA needs this: its supervisor advertises `idb_open` while
    /// every piece of prose ever written about it says `open_idb`.
    aliases: BTreeMap<String, String>,
}

impl Taxonomy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Put `tool` in `category`. A tool may sit in several.
    pub fn assign(&mut self, tool: &str, category: &str) -> &mut Self {
        self.members
            .entry(category.to_owned())
            .or_default()
            .insert(tool.to_owned());
        self
    }

    /// Accept `from` wherever `to` is accepted, for a category or a tool name.
    pub fn alias(&mut self, from: &str, to: &str) -> &mut Self {
        self.aliases.insert(from.to_owned(), to.to_owned());
        self
    }

    /// Derive categories from `group.verb` tool names.
    ///
    /// An engine whose tools are called `patch.nop` and `patch.bytes` has
    /// already written its taxonomy down; asking it to write a second copy as a
    /// `match` is asking for two things to drift. Tools with no `.` are left
    /// uncategorised, and can still be selected by name.
    pub fn by_dot_prefix<T: Advertised>(tools: &[T]) -> Self {
        let mut taxonomy = Self::new();
        for tool in tools {
            let name = tool.advertised().name.as_ref();
            if let Some((group, _)) = name.split_once('.') {
                taxonomy.assign(name, group);
            }
        }
        taxonomy
    }

    /// Category names, sorted. What an error message offers the user.
    pub fn categories(&self) -> Vec<&str> {
        self.members.keys().map(String::as_str).collect()
    }

    pub fn members_of(&self, category: &str) -> Option<&BTreeSet<String>> {
        self.members.get(&self.canonical(category))
    }

    /// Resolve what a user typed to what the engine calls it.
    ///
    /// Exact match first, then the alias table, then the same two again after
    /// case-folding and turning `-`/space into `_`. That last step is mechanism
    /// rather than engine data: `--toolsets Control-Flow` and
    /// `--toolsets control_flow` are the same request in every CLI anyone has
    /// used, and making each engine remember to fold its own input is how one of
    /// them ends up not doing it.
    fn canonical(&self, input: &str) -> String {
        if let Some(target) = self.aliases.get(input) {
            return target.clone();
        }
        if self.members.contains_key(input) {
            return input.to_owned();
        }
        let folded = fold(input);
        if let Some(target) = self.aliases.get(&folded) {
            return target.clone();
        }
        folded
    }
}

/// A configured policy: what this server offers after the user's narrowing.
#[derive(Debug, Clone)]
pub struct ToolPolicy {
    enabled: BTreeSet<String>,
    active: bool,
}

impl ToolPolicy {
    /// Everything on. The default an engine starts from, and what it keeps when
    /// nobody passes a flag.
    pub fn unrestricted() -> Self {
        Self {
            enabled: BTreeSet::new(),
            active: false,
        }
    }

    /// Start configuring a policy over `catalog`.
    ///
    /// `catalog` is the surface being governed — the same slice the engine would
    /// hand to `tools/list`. Both the set of legal names and each tool's
    /// `readOnlyHint` are read from it, so a policy cannot disagree with the
    /// catalog it was built against.
    pub fn builder<T: Advertised>(catalog: &[T]) -> PolicyBuilder<'_> {
        PolicyBuilder::new(catalog)
    }

    pub fn allows(&self, tool: &str) -> bool {
        !self.active || self.enabled.contains(tool)
    }

    /// Whether anything was actually narrowed.
    ///
    /// An engine logs its startup banner off this: "42 of 47 tools" is worth
    /// saying, "47 of 47" is noise.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Drop everything this policy refuses.
    ///
    /// Takes and returns the catalog rather than borrowing it, so the call site
    /// reads as one step and cannot advertise the unfiltered list by forgetting
    /// to reassign.
    #[must_use]
    pub fn advertise<T: Advertised>(&self, catalog: Vec<T>) -> Vec<T> {
        catalog
            .into_iter()
            .filter(|tool| self.allows(tool.advertised().name.as_ref()))
            .collect()
    }
}

/// Fluent construction for [`ToolPolicy`].
///
/// A builder rather than a six-argument `from_inputs`, which is what the two
/// copies in IDA grew into: three `&[String]`s and a bool in a row is a call
/// site nobody can read, and swapping `tools` for `exclude_tools` type-checks.
#[derive(Debug)]
pub struct PolicyBuilder<'a> {
    /// name -> writes (i.e. `readOnlyHint` is not `true`)
    catalog: BTreeMap<String, bool>,
    taxonomy: Taxonomy,
    essential: &'a [&'a str],
    include_categories: Vec<String>,
    include_tools: Vec<String>,
    exclude_tools: Vec<String>,
    read_only: bool,
}

impl<'a> PolicyBuilder<'a> {
    fn new<T: Advertised>(catalog: &[T]) -> Self {
        Self {
            catalog: catalog
                .iter()
                .map(|entry| {
                    let tool = entry.advertised();
                    let writes = !matches!(
                        tool.annotations
                            .as_ref()
                            .and_then(|annotations| annotations.read_only_hint),
                        Some(true)
                    );
                    (tool.name.to_string(), writes)
                })
                .collect(),
            taxonomy: Taxonomy::new(),
            essential: &[],
            include_categories: Vec::new(),
            include_tools: Vec::new(),
            exclude_tools: Vec::new(),
            read_only: false,
        }
    }

    pub fn taxonomy(mut self, taxonomy: Taxonomy) -> Self {
        self.taxonomy = taxonomy;
        self
    }

    /// Tools that survive every narrowing except an explicit exclusion.
    ///
    /// Session lifecycle is what this exists for, and it is needed in two
    /// directions that look unrelated until you hit both:
    ///
    /// * `--read-only` would drop `session.open`, which is honestly annotated as
    ///   mutating — it takes a license seat and starts a process.
    /// * `--toolsets patch` would drop it too, for the unrelated reason that
    ///   opening a view is not patching.
    ///
    /// Either way the result is a server whose every remaining tool answers
    /// "needs `view`" and nothing that can hand one out. That is not a narrower
    /// server, it is a broken one, so this is one concept rather than two
    /// exemptions that each cover half the problem.
    ///
    /// An explicit `--exclude-tools` still removes them: naming a tool is a
    /// clearer statement of intent than picking a category, and an escape hatch
    /// that cannot be closed is its own kind of surprise.
    pub fn essential(mut self, tools: &'a [&'a str]) -> Self {
        self.essential = tools;
        self
    }

    /// Categories to include. Accepts `a,b` in one string as well as repeats,
    /// so `--toolsets=a,b` and `--toolsets a --toolsets b` mean the same thing.
    pub fn include_categories(mut self, input: &[String]) -> Self {
        self.include_categories = split(input);
        self
    }

    pub fn include_tools(mut self, input: &[String]) -> Self {
        self.include_tools = split(input);
        self
    }

    pub fn exclude_tools(mut self, input: &[String]) -> Self {
        self.exclude_tools = split(input);
        self
    }

    pub fn read_only(mut self, yes: bool) -> Self {
        self.read_only = yes;
        self
    }

    /// Compose the four inputs in the order the module documents.
    pub fn build(self) -> Result<ToolPolicy, PolicyError> {
        let active = !self.include_categories.is_empty()
            || !self.include_tools.is_empty()
            || !self.exclude_tools.is_empty()
            || self.read_only;

        // 1. No include named → the whole catalog. An include named → nothing,
        //    so that selecting one category narrows instead of adding to "all".
        let has_include = !self.include_categories.is_empty() || !self.include_tools.is_empty();
        let mut enabled: BTreeSet<String> = if has_include {
            BTreeSet::new()
        } else {
            self.catalog.keys().cloned().collect()
        };

        // 2. Categories, then individual tools.
        for category in &self.include_categories {
            let members =
                self.taxonomy
                    .members_of(category)
                    .ok_or_else(|| PolicyError::UnknownCategory {
                        name: category.clone(),
                        known: self
                            .taxonomy
                            .categories()
                            .into_iter()
                            .map(str::to_owned)
                            .collect(),
                    })?;
            // A taxonomy may name a tool this catalog does not carry — IDA's
            // supervisor advertises a subset of the native catalog. Intersect
            // rather than trusting the table.
            enabled.extend(
                members
                    .iter()
                    .filter(|name| self.catalog.contains_key(*name))
                    .cloned(),
            );
        }
        for tool in &self.include_tools {
            enabled.insert(self.resolve(tool)?);
        }

        // 2b. Whatever the engine declared essential, regardless of what was
        //     selected. Only meaningful when an include narrowed things: with no
        //     include these are already in.
        if has_include {
            enabled.extend(
                self.essential
                    .iter()
                    .filter(|name| self.catalog.contains_key(**name))
                    .map(|name| (*name).to_owned()),
            );
        }

        // 3. Exclusion wins over inclusion, always — including over essential.
        for tool in &self.exclude_tools {
            enabled.remove(&self.resolve(tool)?);
        }

        // 4. Read-only, minus whatever the engine exempted.
        if self.read_only {
            enabled.retain(|name| {
                self.essential.contains(&name.as_str())
                    || !self.catalog.get(name).copied().unwrap_or(true)
            });
        }

        // "Empty" means nothing that can do work, not literally nothing. The
        // essential tools are the ones that let *other* tools be used, so a
        // selection that left only those left a server which can open a view and
        // then do nothing with it — the same dead end as an empty catalog, and
        // worth the same error rather than a healthy-looking start-up.
        if !enabled
            .iter()
            .any(|name| !self.essential.contains(&name.as_str()))
        {
            return Err(PolicyError::Empty);
        }

        Ok(ToolPolicy { enabled, active })
    }

    fn resolve(&self, input: &str) -> Result<String, PolicyError> {
        let canonical = self.taxonomy.canonical(input);
        if self.catalog.contains_key(&canonical) {
            return Ok(canonical);
        }
        Err(PolicyError::UnknownTool(input.to_owned()))
    }
}

/// The four flags, defined once so that three engines cannot spell them
/// differently.
///
/// This is the same move [`SessionSpec`](crate::session::SessionSpec) makes for
/// `--input`/`--idb`: the flag names, the help text and the comma-splitting are
/// part of "the three engines feel alike", and an engine that writes its own
/// `--read-only` will eventually write it with a different meaning.
///
/// Deliberately no `.env(..)`: that needs clap's `env` feature, and cargo
/// unifies features across the whole build graph, so turning it on here turns it
/// on for every crate in every engine's build. An engine that wants
/// `IDA_MCP_READ_ONLY` adds `.env(..)` to the [`Arg`] it gets back.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyArgs {
    pub toolsets: Vec<String>,
    pub tools: Vec<String>,
    pub exclude_tools: Vec<String>,
    pub read_only: bool,
}

pub const TOOLSETS_ARG: &str = "__vibrev_toolsets";
pub const TOOLS_ARG: &str = "__vibrev_tools";
pub const EXCLUDE_TOOLS_ARG: &str = "__vibrev_exclude_tools";
pub const READ_ONLY_ARG: &str = "__vibrev_read_only";

impl PolicyArgs {
    /// The flags, ready to hang on a clap root.
    ///
    /// All four are `global(true)`, which is what puts their values into every
    /// level of `ArgMatches` — including the leaf a derived `tool` subcommand
    /// resolves to, which is otherwise reached before the root is parsed into a
    /// struct at all.
    pub fn args() -> Vec<Arg> {
        vec![
            Arg::new(TOOLSETS_ARG)
                .long("toolsets")
                .global(true)
                .action(ArgAction::Append)
                .value_name("CATEGORY")
                .help("Only expose tools in these categories (comma-separated or repeated). Naming any is a narrowing, not an addition to 'all'"),
            Arg::new(TOOLS_ARG)
                .long("tools")
                .global(true)
                .action(ArgAction::Append)
                .value_name("TOOL")
                .help("Also expose these tools, on top of --toolsets"),
            Arg::new(EXCLUDE_TOOLS_ARG)
                .long("exclude-tools")
                .global(true)
                .action(ArgAction::Append)
                .value_name("TOOL")
                .help("Exclude these tools. Exclusion always wins over inclusion"),
            Arg::new(READ_ONLY_ARG)
                .long("read-only")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Only expose tools that do not mutate the target. Driven by each tool's own readOnlyHint, not a hand-kept list"),
        ]
    }

    /// Read the flags back out of any level of `ArgMatches`.
    ///
    /// `try_get_*` rather than `get_*`: a command tree that never registered
    /// these — an engine that has not adopted the policy yet, or a unit test
    /// building a bare `Command` — should read as "nothing selected" rather than
    /// panic.
    pub fn read(matches: &ArgMatches) -> Self {
        fn many(matches: &ArgMatches, id: &str) -> Vec<String> {
            matches
                .try_get_many::<String>(id)
                .ok()
                .flatten()
                .map(|values| values.cloned().collect())
                .unwrap_or_default()
        }

        Self {
            toolsets: many(matches, TOOLSETS_ARG),
            tools: many(matches, TOOLS_ARG),
            exclude_tools: many(matches, EXCLUDE_TOOLS_ARG),
            read_only: matches
                .try_get_one::<bool>(READ_ONLY_ARG)
                .ok()
                .flatten()
                .copied()
                .unwrap_or(false),
        }
    }

    /// Whether the user asked for anything at all.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Feed these into a builder the engine has already given a taxonomy and its
    /// essential tools.
    pub fn apply<'a>(&'a self, builder: PolicyBuilder<'a>) -> PolicyBuilder<'a> {
        builder
            .include_categories(&self.toolsets)
            .include_tools(&self.tools)
            .exclude_tools(&self.exclude_tools)
            .read_only(self.read_only)
    }
}

/// An MCP server with a [`ToolPolicy`] in front of it.
///
/// Wrapping rather than overriding in place, for one concrete reason: rmcp's
/// `#[tool_handler]` generates `list_tools` only when the impl block does not
/// already have one, and the generated body sets `ttl_ms` and `cache_scope`
/// according to the negotiated protocol version. An engine that hand-writes
/// `list_tools` to add a `retain` silently stops sending those. Here the inner
/// handler still produces the result — macro-generated, protocol fields and all
/// — and this layer only removes entries from it.
///
/// Everything with a trait default that would otherwise bypass the inner handler
/// is forwarded. `discover` is the deliberate exception: its default builds an
/// answer out of `self.supported_protocol_versions()` and `self.get_info()`, so
/// leaving it alone routes those through this wrapper, which is what we want —
/// forwarding it would ask the inner handler to describe a server that is not
/// the one the client is talking to.
#[derive(Debug, Clone)]
pub struct Governed<S> {
    inner: S,
    policy: Arc<ToolPolicy>,
}

impl<S> Governed<S> {
    pub fn new(inner: S, policy: Arc<ToolPolicy>) -> Self {
        Self { inner, policy }
    }

    pub fn policy(&self) -> &ToolPolicy {
        &self.policy
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }
}

/// What a client is told when the policy refuses a call.
///
/// A JSON-RPC error rather than a `CallToolResult` with `isError: true`. The
/// distinction the MCP spec draws is whether the *tool* ran and failed; a tool
/// this server does not offer never ran, so reporting it as a tool failure would
/// tell a model to read the error and retry with different arguments.
///
/// The message names the flags, because the only way this happens is that
/// somebody passed one.
fn refusal(name: &str) -> ErrorData {
    ErrorData::invalid_params(
        format!(
            "tool '{name}' is not enabled on this server \
             (--toolsets/--tools/--exclude-tools/--read-only)"
        ),
        None,
    )
}

impl<S: ServerHandler + Send + Sync> Decorator for Governed<S> {
    type Inner = S;

    fn inner(&self) -> &S {
        &self.inner
    }

    async fn list_tools(
        &self,
        params: Option<PaginatedRequestParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let mut result = self.inner.list_tools(params, ctx).await?;
        if self.policy.is_active() {
            result
                .tools
                .retain(|tool| self.policy.allows(tool.name.as_ref()));
        }
        Ok(result)
    }

    async fn call_tool(
        &self,
        params: CallToolRequestParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        if !self.policy.allows(params.name.as_ref()) {
            return Err(refusal(params.name.as_ref()));
        }
        self.inner.call_tool(params, ctx).await
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.policy
            .allows(name)
            .then(|| self.inner.get_tool(name))
            .flatten()
    }
}

crate::decorated_handler!(Governed<S>, generic S: ServerHandler + Send + Sync);

/// Case and separator folding for a name a user typed.
fn fold(input: &str) -> String {
    input.trim().to_lowercase().replace(['-', ' '], "_")
}

/// `["a,b", " c "]` -> `["a", "b", "c"]`.
///
/// Both spellings reach us in the wild: a shell user repeats the flag, an MCP
/// client config writes one comma-separated string. Treating them differently
/// would be a difference nobody could discover except by being surprised.
fn split(input: &[String]) -> Vec<String> {
    input
        .iter()
        .flat_map(|entry| entry.split(','))
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::{Tool, ToolAnnotations};
    use serde_json::{Map, Value, json};
    use std::sync::Arc;

    fn tool(name: &'static str, read_only: bool) -> Tool {
        Tool::new(
            name,
            "does a thing",
            Arc::new(
                json!({"type": "object"})
                    .as_object()
                    .expect("object")
                    .clone(),
            ) as Arc<Map<String, Value>>,
        )
        .with_annotations(ToolAnnotations::new().read_only(read_only))
    }

    /// A catalog shaped like BN's: `group.verb` names, a lifecycle tool that
    /// writes, a patch group, and arbitrary code execution.
    fn sample() -> Vec<Tool> {
        vec![
            tool("session.open", false),
            tool("session.list", true),
            tool("binary.functions", true),
            tool("binary.strings", true),
            tool("patch.nop", false),
            tool("patch.bytes", false),
            tool("script.python", false),
        ]
    }

    fn names(policy: &ToolPolicy, catalog: Vec<Tool>) -> Vec<String> {
        policy
            .advertise(catalog)
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect()
    }

    fn builder() -> PolicyBuilder<'static> {
        // Leaked so the borrow in `builder` can outlive this call; tests only.
        let catalog: &'static [Tool] = Box::leak(sample().into_boxed_slice());
        const ESSENTIAL: &[&str] = &["session.open", "session.list"];
        ToolPolicy::builder(catalog)
            .taxonomy(Taxonomy::by_dot_prefix(catalog))
            .essential(ESSENTIAL)
    }

    /// The default is everything, including the tool that runs arbitrary code.
    /// An engine that ships a tool ships it; withholding one until a flag is
    /// found is a capability the operator discovers by asking why it is missing.
    #[test]
    fn no_inputs_enables_everything_and_reports_itself_inactive() {
        let policy = builder().build().expect("policy");
        assert_eq!(names(&policy, sample()).len(), 7);
        assert!(policy.allows("script.python"));
        assert!(!policy.is_active());
    }

    /// The first composition step: naming a category narrows, it does not add.
    #[test]
    fn a_category_replaces_the_implicit_everything() {
        let policy = builder()
            .include_categories(&["patch".to_string()])
            .build()
            .expect("policy");
        // Catalog order, not sorted: clients render `tools/list` in the order
        // they receive it, so filtering must not quietly reshuffle what
        // survives.
        assert_eq!(
            names(&policy, sample()),
            ["session.open", "session.list", "patch.nop", "patch.bytes"],
            "the patch group, plus the lifecycle without which none of it is callable"
        );
        assert!(policy.is_active());
    }

    #[test]
    fn dot_prefixes_are_a_taxonomy_without_anyone_writing_one() {
        let taxonomy = Taxonomy::by_dot_prefix(&sample());
        assert_eq!(
            taxonomy.categories(),
            ["binary", "patch", "script", "session"]
        );
    }

    #[test]
    fn individual_tools_add_to_the_named_categories() {
        let policy = builder()
            .include_categories(&["patch".to_string()])
            .include_tools(&["binary.strings".to_string()])
            .build()
            .expect("policy");
        assert_eq!(
            names(&policy, sample()),
            [
                "session.open",
                "session.list",
                "binary.strings",
                "patch.nop",
                "patch.bytes"
            ]
        );
    }

    /// Step 3, and the reason the order is written down: the two flags disagree
    /// on purpose and one of them has to win definitely.
    #[test]
    fn exclusion_wins_over_inclusion() {
        let policy = builder()
            .include_categories(&["patch".to_string()])
            .exclude_tools(&["patch.bytes".to_string()])
            .build()
            .expect("policy");
        assert_eq!(
            names(&policy, sample()),
            ["session.open", "session.list", "patch.nop"]
        );
    }

    /// An engine can be started read-only, and the deny list is derived rather
    /// than kept.
    #[test]
    fn read_only_strips_every_writer_and_keeps_the_lifecycle() {
        let policy = builder().read_only(true).build().expect("policy");
        assert_eq!(
            names(&policy, sample()),
            [
                // Writes, and stays: a read-only server that cannot open a view
                // cannot read either.
                "session.open",
                "session.list",
                "binary.functions",
                "binary.strings",
            ]
        );
    }

    /// The other half of "no second list": a tool nobody has heard of is denied
    /// the moment its annotation says it writes.
    #[test]
    fn a_new_writer_is_denied_without_anyone_updating_a_list() {
        let mut extended = sample();
        extended.push(tool("type.apply", false));
        let extended: &'static [Tool] = Box::leak(extended.into_boxed_slice());

        let policy = ToolPolicy::builder(extended)
            .essential(&["session.open"])
            .read_only(true)
            .build()
            .expect("policy");
        assert!(!policy.allows("type.apply"));
    }

    /// An absent hint counts as writing. The opposite default lets a mutating
    /// tool survive `--read-only` by omission — the one place this module errs
    /// towards offering less.
    #[test]
    fn a_tool_with_no_hint_is_treated_as_a_writer() {
        let bare: &'static [Tool] = Box::leak(
            vec![
                Tool::new(
                    "mystery",
                    "no annotations at all",
                    Arc::new(json!({"type": "object"}).as_object().expect("o").clone())
                        as Arc<Map<String, Value>>,
                ),
                tool("binary.strings", true),
            ]
            .into_boxed_slice(),
        );
        let policy = ToolPolicy::builder(bare)
            .read_only(true)
            .build()
            .expect("policy");
        assert!(!policy.allows("mystery"));
        assert!(policy.allows("binary.strings"));
    }

    #[test]
    fn a_misspelled_category_says_what_the_engine_actually_has() {
        let error = builder()
            .include_categories(&["patches".to_string()])
            .build()
            .unwrap_err();
        let PolicyError::UnknownCategory { name, known } = &error else {
            panic!("wrong error: {error}");
        };
        assert_eq!(name, "patches");
        assert!(known.contains(&"patch".to_string()));
        assert!(error.to_string().contains("binary, patch, script, session"));
    }

    #[test]
    fn a_misspelled_tool_is_refused_rather_than_ignored() {
        assert_eq!(
            builder()
                .include_tools(&["patch.nope".to_string()])
                .build()
                .unwrap_err(),
            PolicyError::UnknownTool("patch.nope".to_string())
        );
    }

    /// IDA's case: prose and the advertised surface disagree on a name, and the
    /// alias is engine data rather than something kit could guess.
    #[test]
    fn an_alias_reaches_the_tool_the_engine_actually_advertises() {
        let catalog: &'static [Tool] = Box::leak(sample().into_boxed_slice());
        let mut taxonomy = Taxonomy::by_dot_prefix(catalog);
        taxonomy.alias("open_idb", "session.open");

        let policy = ToolPolicy::builder(catalog)
            .taxonomy(taxonomy)
            .include_tools(&["open_idb".to_string()])
            .build()
            .expect("policy");
        assert_eq!(names(&policy, sample()), ["session.open"]);
    }

    /// Case and separator folding, so that a category is the same category
    /// however a user shell-quoted it.
    #[test]
    fn a_category_is_recognised_however_it_was_typed() {
        let mut taxonomy = Taxonomy::new();
        taxonomy.assign("cfg.walk", "control_flow");
        taxonomy.alias("cfg", "control_flow");

        for spelling in [
            "control_flow",
            "Control-Flow",
            "  CONTROL FLOW  ",
            "cfg",
            "CFG",
        ] {
            assert!(
                taxonomy.members_of(spelling).is_some(),
                "{spelling:?} should reach control_flow"
            );
        }
        assert!(taxonomy.members_of("controlflow").is_none(), "not a guess");
    }

    /// One comma-separated string and repeated flags are the same request.
    #[test]
    fn commas_and_repeats_mean_the_same_thing() {
        let commas = builder()
            .include_categories(&["patch,binary".to_string()])
            .build()
            .expect("policy");
        let repeats = builder()
            .include_categories(&["patch".to_string(), " binary ".to_string()])
            .build()
            .expect("policy");
        assert_eq!(names(&commas, sample()), names(&repeats, sample()));
        assert_eq!(
            names(&commas, sample()).len(),
            6,
            "4 selected + 2 essential"
        );
    }

    /// A taxonomy built from the native catalog, applied to the narrower
    /// supervisor face, must not conjure tools that face does not carry.
    #[test]
    fn a_category_cannot_add_a_tool_this_face_does_not_advertise() {
        let wide: &'static [Tool] = Box::leak(sample().into_boxed_slice());
        let narrow: &'static [Tool] = Box::leak(
            vec![tool("patch.nop", false), tool("binary.strings", true)].into_boxed_slice(),
        );

        let policy = ToolPolicy::builder(narrow)
            .taxonomy(Taxonomy::by_dot_prefix(wide))
            .include_categories(&["patch".to_string()])
            .build()
            .expect("policy");
        assert_eq!(
            names(&policy, narrow.to_vec()),
            ["patch.nop"],
            "patch.bytes is in the taxonomy but not on this face"
        );
    }

    #[test]
    fn unrestricted_admits_everything() {
        let policy = ToolPolicy::unrestricted();
        assert!(!policy.is_active());
        assert!(policy.allows("script.python"));
        assert_eq!(names(&policy, sample()).len(), 7);
    }

    #[test]
    fn a_builder_over_an_empty_catalog_has_nothing_to_offer() {
        let empty: &[Tool] = &[];
        assert_eq!(
            ToolPolicy::builder(empty).build().unwrap_err(),
            PolicyError::Empty
        );
    }

    /// The defect an end-to-end run turned up, pinned.
    ///
    /// `--toolsets patch` used to produce a server with eight patch tools and no
    /// `session.open` — and every one of those tools requires a `view` handle
    /// that only `session.open` hands out. Eight tools, zero of them callable.
    ///
    /// It is the same failure as `--read-only` dropping the lifecycle, arriving
    /// by an unrelated route, which is why both are one concept here.
    #[test]
    fn narrowing_to_a_category_still_leaves_a_usable_server() {
        for narrowing in [
            builder().include_categories(&["patch".to_string()]),
            builder().include_tools(&["patch.nop".to_string()]),
            builder().read_only(true),
        ] {
            let policy = narrowing.build().expect("policy");
            assert!(policy.allows("session.open"), "no way to obtain a view");
        }
    }

    /// …but naming it explicitly still removes it. Picking a category is a
    /// guess about what you need; naming a tool is a statement.
    #[test]
    fn an_explicit_exclusion_reaches_even_an_essential_tool() {
        let policy = builder()
            .exclude_tools(&["session.open".to_string()])
            .build()
            .expect("policy");
        assert!(!policy.allows("session.open"));
        assert!(policy.allows("session.list"));
    }

    /// A selection that leaves only the lifecycle is empty in the sense that
    /// matters: the server can open a view and then do nothing with it.
    #[test]
    fn a_server_with_nothing_but_lifecycle_left_is_empty() {
        assert_eq!(
            builder()
                .include_tools(&["patch.nop".to_string()])
                .exclude_tools(&["patch.nop".to_string()])
                .build()
                .unwrap_err(),
            PolicyError::Empty
        );
    }

    /// The behaviour every engine's wiring rests on.
    ///
    /// A derived `tool` tree is reached through `cli::resolve`, which hands back
    /// the *leaf* subcommand's matches — and that happens before the root is
    /// ever parsed into a struct. So a flag written before the subcommand has to
    /// arrive at the leaf, or `bn tool patch.nop --read-only` would silently
    /// ignore the flag. `global(true)` is what does it, and this pins it.
    #[test]
    fn the_flags_reach_the_leaf_of_a_derived_tool_tree() {
        let command = clap::Command::new("engine")
            .args(PolicyArgs::args())
            .subcommand(
                clap::Command::new("tool")
                    .subcommand(clap::Command::new("patch").subcommand(clap::Command::new("nop"))),
            );
        let matches = command
            .try_get_matches_from([
                "engine",
                "--read-only",
                "--exclude-tools",
                "patch.bytes",
                "tool",
                "patch",
                "nop",
            ])
            .expect("parse");

        let (_, tool) = matches.subcommand().expect("tool");
        let (_, group) = tool.subcommand().expect("patch");
        let (_, leaf) = group.subcommand().expect("nop");

        let args = PolicyArgs::read(leaf);
        assert!(args.read_only, "the flag has to survive three levels down");
        assert_eq!(args.exclude_tools, ["patch.bytes"]);
        assert_eq!(PolicyArgs::read(&matches), args, "root and leaf agree");
    }

    /// An engine that has not adopted the policy reads as "nothing selected"
    /// rather than panicking on an unregistered argument id.
    #[test]
    fn reading_a_tree_that_never_registered_the_flags_is_not_a_panic() {
        let matches = clap::Command::new("engine")
            .try_get_matches_from(["engine"])
            .expect("parse");
        let args = PolicyArgs::read(&matches);
        assert_eq!(args, PolicyArgs::default());
        assert!(args.is_empty());
    }

    #[test]
    fn apply_carries_every_flag_into_the_builder() {
        let args = PolicyArgs {
            toolsets: vec!["patch".to_string()],
            tools: vec!["binary.strings".to_string()],
            exclude_tools: vec!["patch.bytes".to_string()],
            read_only: false,
        };
        assert!(!args.is_empty());
        let policy = args.apply(builder()).build().expect("policy");
        assert_eq!(
            names(&policy, sample()),
            [
                "session.open",
                "session.list",
                "binary.strings",
                "patch.nop"
            ]
        );
    }

    /// `Governed` refuses through the same policy the catalog was filtered with,
    /// so a tool that is not listed cannot be called by guessing its name.
    #[test]
    fn a_governed_server_hides_and_refuses_the_same_tools() {
        #[derive(Clone, Debug)]
        struct Fake(Vec<Tool>);
        impl ServerHandler for Fake {
            fn get_tool(&self, name: &str) -> Option<Tool> {
                self.0.iter().find(|tool| tool.name == name).cloned()
            }
        }

        let policy = builder().read_only(true).build().expect("policy");
        let governed = Governed::new(Fake(sample()), Arc::new(policy));

        // Named through `ServerHandler` on purpose: `Governed` now carries both
        // that trait and `Decorator`, and it is the one a client reaches.
        assert!(ServerHandler::get_tool(&governed, "binary.strings").is_some());
        assert!(
            ServerHandler::get_tool(&governed, "patch.nop").is_none(),
            "a writer is invisible under --read-only"
        );
        assert!(
            Decorator::inner(&governed).get_tool("patch.nop").is_some(),
            "…and still there underneath, which is why the wrapper has to refuse \
             calls too rather than trusting the catalog"
        );
    }

    #[test]
    fn a_refusal_names_the_flags_that_could_have_caused_it() {
        let message = refusal("patch.nop").message;
        assert!(message.contains("patch.nop"), "{message}");
        assert!(message.contains("--read-only"), "{message}");
    }
}
