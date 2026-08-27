//! The cross-engine tool-surface contract, as something that runs.
//!
//! Each engine carries its own MCP face, which makes consistency between them a
//! convention rather than a compile-time guarantee: nothing in the build forces
//! the three engines to feel alike. This module is that mechanism. It reads a
//! catalog of advertised tools and reports every place the surface departs from
//! what a VibRev client is entitled to assume, so that "the three engines feel
//! alike" stops being a thing a reviewer has to notice by hand.
//!
//! Once kit is a path dependency inside three engines' request paths, a change
//! here can break an engine that is not in this repository, and nothing else in
//! the build would find out before merge.
//!
//! # What is here and what is not
//!
//! The *mechanism* is here. The *lists* are not. Which tools owe an
//! `outputSchema`, and which owe an `analysis_coverage` block, are domain
//! facts about one engine; the moment kit holds a list of IDA tool names it has
//! stopped being shared. So engines pass their own ratchets in:
//!
//! ```no_run
//! # use vibrev_kit::contract::{Audit, OutputSchemas};
//! # fn catalog() -> Vec<rmcp::model::Tool> { Vec::new() }
//! # const CONVERTED: &[&str] = &[];
//! # const OWES_COVERAGE: &[&str] = &[];
//! Audit::new("native")
//!     .output_schemas(OutputSchemas::Staged(CONVERTED))
//!     .require_output_property("analysis_coverage", OWES_COVERAGE)
//!     .run_repeated(catalog)
//!     .assert_clean();
//! ```
//!
//! # Reading a report
//!
//! [`SurfaceReport`] carries findings *and* counts. The counts are not
//! decoration: an audit over an empty catalog, or over tools that all happen to
//! be exempt, would otherwise pass while checking nothing — which is the failure
//! mode a contract test can least afford. [`assert_clean`](SurfaceReport::assert_clean)
//! prints both, and an empty surface is itself a finding.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use rmcp::model::Tool;
use serde_json::Value;

use crate::ToolDef;
use crate::schema::{has_nullable_type_array, null_branch_position};

// Defined at the crate root rather than here: `policy` reads catalogs through
// the same trait, and a scan carrying its own notion of "an advertised tool"
// would be auditing something other than what the policy filters. Re-exported at
// this path so engines that already import it do not have to move.
pub use crate::Advertised;

/// One way a tool surface can be wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    /// The catalog handed in was empty, so nothing was checked.
    EmptySurface,
    /// Two tools share a name; whichever the router reaches second is dead.
    DuplicateName,
    /// Building the catalog twice produced different orders.
    UnstableOrder,
    /// No `title`.
    MissingTitle,
    /// A `title` that is whitespace.
    BlankTitle,
    /// The `title` only restates the tool name.
    TitleRestatesName,
    /// The `title` only restates the first sentence of the description.
    TitleRestatesDescription,
    /// Two tools share a `title`, so a client's picker shows the same label twice.
    DuplicateTitle,
    /// No `annotations` block at all.
    MissingAnnotations,
    /// `annotations` without `readOnlyHint`. Clients gate confirmation prompts
    /// on it, so absent is not a safe default.
    MissingReadOnlyHint,
    /// No `outputSchema` on a tool the engine's ratchet says has one.
    MissingOutputSchema,
    /// An `outputSchema` that describes nothing.
    EmptyOutputSchema,
    /// `$schema` survived into a published document.
    SchemaDialectLeak,
    /// A `$ref` that does not resolve inside the document that carries it.
    DanglingRef,
    /// A `$ref` pointing outside the document.
    NonLocalRef,
    /// An input schema spells optionality as a null branch instead of leaving
    /// the field out of `required`. See [`Audit::nullable_input_branches`].
    NullableInputBranch,
    /// An input schema publishes a numeric `format` a strict consumer does not
    /// know — every `uint*` schemars derives from an unsigned Rust integer. The
    /// wire type for an unsigned quantity is `i64` plus a `range`, and
    /// [`crate::parse_unsigned`] is the way back from it.
    UnportableFormat,
    /// A tool takes a `limit`, so it can hold part of its answer back, and
    /// publishes nothing a caller could read to find out that it did. See
    /// [`crate::page`], which is both the arithmetic and the way to satisfy this.
    SilentTruncation,
    /// A property the engine declared mandatory is missing from an output schema.
    MissingRequiredProperty,
    /// The property is declared but not listed in `required`, so it may vanish
    /// from the wire exactly when it matters.
    PropertyNotRequired,
    /// A ratchet list names a tool that does not exist on this surface.
    StaleRatchetEntry,
    /// A ratchet list is not sorted, so additions to it are not reviewable.
    UnsortedRatchet,
}

impl Rule {
    /// A stable slug, for grepping a CI log.
    pub const fn slug(self) -> &'static str {
        match self {
            Rule::EmptySurface => "empty-surface",
            Rule::DuplicateName => "duplicate-name",
            Rule::UnstableOrder => "unstable-order",
            Rule::MissingTitle => "missing-title",
            Rule::BlankTitle => "blank-title",
            Rule::TitleRestatesName => "title-restates-name",
            Rule::TitleRestatesDescription => "title-restates-description",
            Rule::DuplicateTitle => "duplicate-title",
            Rule::MissingAnnotations => "missing-annotations",
            Rule::MissingReadOnlyHint => "missing-read-only-hint",
            Rule::MissingOutputSchema => "missing-output-schema",
            Rule::EmptyOutputSchema => "empty-output-schema",
            Rule::SchemaDialectLeak => "schema-dialect-leak",
            Rule::DanglingRef => "dangling-ref",
            Rule::NonLocalRef => "non-local-ref",
            Rule::NullableInputBranch => "nullable-input-branch",
            Rule::UnportableFormat => "unportable-format",
            Rule::SilentTruncation => "silent-truncation",
            Rule::MissingRequiredProperty => "missing-required-property",
            Rule::PropertyNotRequired => "property-not-required",
            Rule::StaleRatchetEntry => "stale-ratchet-entry",
            Rule::UnsortedRatchet => "unsorted-ratchet",
        }
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

/// One violation, located.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Which catalog this came from — engines audit several faces.
    pub face: String,
    /// The offending tool, or `None` for a finding about the surface as a whole.
    pub tool: Option<String>,
    pub rule: Rule,
    /// What is wrong, in enough detail to fix it without re-deriving it.
    pub detail: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {}/{}: {}",
            self.rule,
            self.face,
            self.tool.as_deref().unwrap_or("<surface>"),
            self.detail
        )
    }
}

/// How much the audit actually looked at.
///
/// Reported so that a scan which checked nothing cannot read as a pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Checked {
    pub tools: usize,
    pub input_schemas: usize,
    pub output_schemas: usize,
    pub refs: usize,
}

impl Checked {
    fn add(&mut self, other: Checked) {
        self.tools += other.tools;
        self.input_schemas += other.input_schemas;
        self.output_schemas += other.output_schemas;
        self.refs += other.refs;
    }
}

impl fmt::Display for Checked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} tools, {} input schemas, {} output schemas, {} $refs",
            self.tools, self.input_schemas, self.output_schemas, self.refs
        )
    }
}

/// The result of one scan.
#[derive(Debug, Clone, Default)]
pub struct SurfaceReport {
    findings: Vec<Finding>,
    checked: Checked,
}

impl SurfaceReport {
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    pub fn checked(&self) -> Checked {
        self.checked
    }

    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Every finding for one rule — for a test that is staging a fix and wants
    /// to assert on the rest.
    pub fn by_rule(&self, rule: Rule) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(move |f| f.rule == rule)
    }

    /// Fold another face's report into this one, so an engine that advertises
    /// from several catalogs fails once with everything.
    pub fn merge(&mut self, other: SurfaceReport) -> &mut Self {
        self.findings.extend(other.findings);
        self.checked.add(other.checked);
        self
    }

    /// Panic with the whole report unless the surface is clean.
    ///
    /// The counts go into the message on purpose: the useful failure is "12
    /// findings", and the *dangerous* pass is "0 findings over 0 tools".
    #[track_caller]
    pub fn assert_clean(&self) {
        assert!(self.is_clean(), "{self}");
    }
}

impl fmt::Display for SurfaceReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "tool-surface contract: {} finding(s) over {}",
            self.findings.len(),
            self.checked
        )?;
        for finding in &self.findings {
            writeln!(f, "  {finding}")?;
        }
        Ok(())
    }
}

/// How strictly `outputSchema` is required on this face.
#[derive(Debug, Clone, Copy)]
pub enum OutputSchemas<'a> {
    /// Every advertised tool must publish one. The end state.
    Required,
    /// Staged conversion: only the named tools are checked, so unconverted ones
    /// do not block CI. The list itself is checked for stale entries and for
    /// being sorted — a ratchet nobody can review is not a ratchet.
    Staged(&'a [&'a str]),
    /// Not checked. For a face that legitimately has none.
    Unchecked,
}

#[derive(Debug, Clone, Copy)]
struct RequiredProperty<'a> {
    name: &'a str,
    tools: &'a [&'a str],
}

/// Which of a tool's two published documents is being walked.
///
/// They do not owe the same things. A client hands `inputSchema` to a model
/// provider, which parses it against a subset of JSON Schema and refuses what it
/// does not recognise; `outputSchema` is read by a validator, which by
/// specification ignores keywords and formats it does not know. Two of the rules
/// below are therefore input-only, and this is what says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Face {
    Input,
    Output,
}

impl Face {
    fn label(self) -> &'static str {
        match self {
            Face::Input => "input",
            Face::Output => "output",
        }
    }
}

/// The `format` values a strict consumer of `inputSchema` is known to accept on
/// a number.
///
/// Vertex/Gemini's function-declaration parser takes these four and rejects the
/// rest, which includes every `uint*` schemars derives from an unsigned Rust
/// integer — `usize` alone becomes `uint`, `u32` becomes `uint32`. It also
/// includes `int8` and `int16`, which are just as unknown to it as `uint32` is.
const PORTABLE_FORMATS: [&str; 4] = ["double", "float", "int32", "int64"];

/// A configured scan. Build it once per face, run it against that face's catalog.
#[derive(Debug, Clone)]
pub struct Audit<'a> {
    face: &'a str,
    output_schemas: OutputSchemas<'a>,
    required_properties: Vec<RequiredProperty<'a>>,
    nullable_input_branches: bool,
    repeats: usize,
}

impl<'a> Audit<'a> {
    /// `face` names the catalog, and shows up in every finding. Engines that
    /// advertise from several places should give each one a distinct name.
    pub fn new(face: &'a str) -> Self {
        Self {
            face,
            output_schemas: OutputSchemas::Required,
            required_properties: Vec::new(),
            nullable_input_branches: true,
            repeats: 3,
        }
    }

    pub fn output_schemas(mut self, policy: OutputSchemas<'a>) -> Self {
        self.output_schemas = policy;
        self
    }

    /// Declare that the named tools must publish `name` as a *required*
    /// property of their output schema.
    ///
    /// `analysis_coverage` is the case this exists for: the whole point
    /// of the field is that it cannot go missing, and an `Option` with
    /// `skip_serializing_if` would satisfy "the schema mentions it" while
    /// dropping it from the wire exactly when analysis is incomplete. So
    /// mentioning it is not enough — it has to be in `required`.
    ///
    /// The mechanism is here; the list is the engine's.
    pub fn require_output_property(mut self, name: &'a str, tools: &'a [&'a str]) -> Self {
        self.required_properties
            .push(RequiredProperty { name, tools });
        self
    }

    /// Whether an input schema may express optionality as a null branch.
    ///
    /// On by default. schemars writes
    /// `Option<T>` as `anyOf: [T, {type:"null"}]` or `type: ["T","null"]`; IDA
    /// flattens both at its MCP exit, BN does not, so today the same
    /// `Option<u32>` parameter is advertised with two different structures by
    /// two engines that are supposed to feel alike. A client that generates
    /// argument forms from `inputSchema` sees a different form per engine.
    ///
    /// This is deliberately *not* applied to output schemas. There the null
    /// branch is true: an `Option` field without `skip_serializing_if` really is
    /// emitted as `null`, and a schema claiming otherwise would fail validation
    /// on a correct response.
    ///
    /// Turn it off only to stage the fix, and only with the reason written down.
    pub fn nullable_input_branches(mut self, allowed: bool) -> Self {
        self.nullable_input_branches = !allowed;
        self
    }

    /// How many times [`run_repeated`](Self::run_repeated) rebuilds the catalog.
    pub fn repeats(mut self, times: usize) -> Self {
        self.repeats = times.max(2);
        self
    }

    /// Scan one catalog.
    #[must_use]
    pub fn run<T: Advertised>(&self, tools: &[T]) -> SurfaceReport {
        let mut report = SurfaceReport::default();
        self.scan(tools, &mut report);
        report
    }

    /// Scan a catalog that is built on demand, checking that building it twice
    /// yields the same order.
    ///
    /// Order is part of the surface: clients render `tools/list` in the order
    /// they receive it, and a catalog assembled through a hash map reshuffles
    /// itself between runs — which shows up as a snapshot test that fails at
    /// random rather than as anything anyone would recognise as a bug.
    #[must_use]
    pub fn run_repeated<T, F>(&self, mut build: F) -> SurfaceReport
    where
        T: Advertised,
        F: FnMut() -> Vec<T>,
    {
        let first = build();
        let baseline: Vec<String> = names(&first);

        let mut report = SurfaceReport::default();
        for round in 1..self.repeats {
            let again = names(&build());
            if again != baseline {
                report.findings.push(Finding {
                    face: self.face.to_string(),
                    tool: None,
                    rule: Rule::UnstableOrder,
                    detail: format!(
                        "build #{round} listed the tools in a different order than build #0; \
                         first divergence at index {}",
                        baseline
                            .iter()
                            .zip(again.iter())
                            .position(|(a, b)| a != b)
                            .unwrap_or_else(|| baseline.len().min(again.len()))
                    ),
                });
                break;
            }
        }

        self.scan(&first, &mut report);
        report
    }

    // -- the scan itself ----------------------------------------------------

    fn scan<T: Advertised>(&self, tools: &[T], report: &mut SurfaceReport) {
        if tools.is_empty() {
            report.findings.push(self.surface_finding(
                Rule::EmptySurface,
                "the audited catalog is empty, so this test asserts nothing".to_string(),
            ));
            return;
        }

        self.check_names_and_titles(tools, report);

        for tool in tools {
            let tool = tool.advertised();
            report.checked.tools += 1;
            self.check_title(tool, report);
            self.check_annotations(tool, report);
            self.check_input_schema(tool, report);
            self.check_output_schema(tool, report);
            self.check_pagination(tool, report);
        }

        self.check_ratchets(tools, report);
    }

    fn check_names_and_titles<T: Advertised>(&self, tools: &[T], report: &mut SurfaceReport) {
        let mut by_name: BTreeMap<&str, usize> = BTreeMap::new();
        let mut by_title: BTreeMap<&str, Vec<&str>> = BTreeMap::new();

        for tool in tools {
            let tool = tool.advertised();
            *by_name.entry(tool.name.as_ref()).or_default() += 1;
            if let Some(title) = tool
                .title
                .as_deref()
                .map(str::trim)
                .filter(|t| !t.is_empty())
            {
                by_title.entry(title).or_default().push(tool.name.as_ref());
            }
        }

        for (name, count) in by_name {
            if count > 1 {
                report.findings.push(self.finding(
                    name,
                    Rule::DuplicateName,
                    format!("advertised {count} times; only one of them is reachable"),
                ));
            }
        }

        for (title, owners) in by_title {
            if owners.len() > 1 {
                report.findings.push(self.finding(
                    owners[0],
                    Rule::DuplicateTitle,
                    format!("{owners:?} all publish the title {title:?}"),
                ));
            }
        }
    }

    /// A title that repeats the name, or the first sentence of the description,
    /// spends a field a client shows in a picker and says nothing new with it.
    fn check_title(&self, tool: &Tool, report: &mut SurfaceReport) {
        let name = tool.name.as_ref();
        let Some(title) = tool.title.as_deref() else {
            report.findings.push(self.finding(
                name,
                Rule::MissingTitle,
                "no title; declare one at the tool site".to_string(),
            ));
            return;
        };
        if title.trim().is_empty() {
            report.findings.push(self.finding(
                name,
                Rule::BlankTitle,
                "the title is whitespace".to_string(),
            ));
            return;
        }
        if title.to_lowercase().replace([' ', '-'], "_") == name.to_lowercase() {
            report.findings.push(self.finding(
                name,
                Rule::TitleRestatesName,
                format!("the title {title:?} just restates the tool name"),
            ));
        }
        if let Some(description) = tool.description.as_deref() {
            let first_sentence = description
                .split_once(". ")
                .map_or(description, |(first, _)| first)
                .trim_end_matches('.')
                .trim();
            if title
                .trim_end_matches('.')
                .eq_ignore_ascii_case(first_sentence)
            {
                report.findings.push(self.finding(
                    name,
                    Rule::TitleRestatesDescription,
                    format!("the title {title:?} just restates the description"),
                ));
            }
        }
    }

    fn check_annotations(&self, tool: &Tool, report: &mut SurfaceReport) {
        let name = tool.name.as_ref();
        let Some(annotations) = tool.annotations.as_ref() else {
            report.findings.push(self.finding(
                name,
                Rule::MissingAnnotations,
                "no annotations block".to_string(),
            ));
            return;
        };
        if annotations.read_only_hint.is_none() {
            report.findings.push(
                self.finding(
                    name,
                    Rule::MissingReadOnlyHint,
                    "annotations without readOnlyHint; clients gate confirmation on it, \
                 so absent is not a safe default"
                        .to_string(),
                ),
            );
        }
    }

    fn check_input_schema(&self, tool: &Tool, report: &mut SurfaceReport) {
        let name = tool.name.as_ref();
        let document = Value::Object((*tool.input_schema).clone());
        report.checked.input_schemas += 1;
        self.walk_schema(name, Face::Input, &document, report);
    }

    fn check_output_schema(&self, tool: &Tool, report: &mut SurfaceReport) {
        let name = tool.name.as_ref();
        let required = match self.output_schemas {
            OutputSchemas::Required => true,
            OutputSchemas::Staged(list) => list.contains(&name),
            OutputSchemas::Unchecked => false,
        };

        let Some(schema) = tool.output_schema.as_ref() else {
            if required {
                report.findings.push(self.finding(
                    name,
                    Rule::MissingOutputSchema,
                    "publishes no outputSchema".to_string(),
                ));
            }
            return;
        };

        report.checked.output_schemas += 1;

        // Checked whether or not the tool is on the ratchet: a schema that is
        // present is a schema clients will read.
        const ROOTS: [&str; 5] = ["type", "anyOf", "oneOf", "allOf", "$ref"];
        if schema.is_empty() || !ROOTS.iter().any(|key| schema.contains_key(*key)) {
            report.findings.push(self.finding(
                name,
                Rule::EmptyOutputSchema,
                "publishes an outputSchema shell that describes nothing".to_string(),
            ));
        }

        let document = Value::Object((**schema).clone());
        self.walk_schema(name, Face::Output, &document, report);
    }

    /// A tool that can hold part of its answer back has to say so.
    ///
    /// The only rule that reads both faces at once, because the defect is a
    /// relationship between them: a `limit` on the input face is permission to
    /// return less than everything, and nothing on the output face is obliged to
    /// mention that the permission was used. A hundred entries is a plausible
    /// answer whether a hundred exist or ten thousand do, so the caller cannot
    /// detect the difference — it reads as a smaller database, not as an error.
    ///
    /// Two strengths, because tools take a `limit` for two reasons:
    ///
    /// - With an `offset`, the tool is *paging*, and the caller has been invited
    ///   to come back for the rest. `next_offset` is where. Nothing else will
    ///   do: `total` says more exists without saying where it starts, and
    ///   arithmetic on `offset + len` is exactly the calculation five different
    ///   copies of got wrong before [`crate::page::next_offset`] existed.
    /// - Without one, the tool is *capping a scan* — there is no second page to
    ///   ask for, and the honest answer is only that this one is not everything.
    ///   `total`, `truncated` or `next_offset` each say it.
    ///
    /// Where the answer may live is [`page_state`]'s business: a batch tool pages
    /// each of its entries separately, so the root is not the only honest place
    /// to put it.
    fn check_pagination(&self, tool: &Tool, report: &mut SurfaceReport) {
        let name = tool.name.as_ref();
        let takes = root_properties(&tool.input_schema);
        if !takes.contains("limit") {
            return;
        }
        // An absent output schema is `MissingOutputSchema`'s finding to make,
        // and reporting both would blame one tool twice for one omission.
        let Some(output) = tool.output_schema.as_ref() else {
            return;
        };
        let publishes = page_state(output);

        if takes.contains("offset") {
            if !publishes.contains("next_offset") {
                report.findings.push(
                    self.finding(
                        name,
                        Rule::SilentTruncation,
                        "takes offset and limit but publishes no next_offset; the caller is \
                     invited to page and not told where the next page starts. Build the \
                     answer with vibrev_kit::page::Page, which computes it"
                            .to_string(),
                    ),
                );
            }
            return;
        }

        const HONEST: [&str; 3] = ["next_offset", "total", "truncated"];
        if !HONEST.iter().any(|key| publishes.contains(key)) {
            report.findings.push(self.finding(
                name,
                Rule::SilentTruncation,
                format!(
                    "takes a limit and publishes none of {}; a full page and the whole \
                     answer are the same payload, so the caller cannot tell them apart",
                    HONEST.join(" / ")
                ),
            ));
        }
    }

    /// One pass over a published document, collecting everything that is a
    /// property of the *document* rather than of one keyword.
    fn walk_schema(&self, tool: &str, face: Face, document: &Value, report: &mut SurfaceReport) {
        // Both input-only rules, and for the same reason in each case: what a
        // provider's strict parser rejects in a document it is handed as a
        // function declaration is the plain truth in a document describing a
        // response. See `nullable_input_branches` and `Rule::UnportableFormat`.
        let strict = matches!(face, Face::Input);
        let flag_nullable = strict && self.nullable_input_branches;
        let face = face.label();

        let root = document.as_object().cloned().unwrap_or_default();
        let mut findings = Vec::new();
        let mut refs = 0usize;

        visit(document, String::new(), &mut |node, path| {
            let Some(map) = node.as_object() else { return };

            if map.contains_key("$schema") {
                findings.push((
                    Rule::SchemaDialectLeak,
                    format!("{face} schema leaks $schema at {}", location(path)),
                ));
            }

            if let Some(target) = map.get("$ref").and_then(Value::as_str) {
                refs += 1;
                match target.strip_prefix('#') {
                    None => findings.push((
                        Rule::NonLocalRef,
                        format!(
                            "{face} schema has a non-local $ref {target:?} at {}",
                            location(path)
                        ),
                    )),
                    Some(pointer) if document.pointer(pointer).is_none() => findings.push((
                        Rule::DanglingRef,
                        format!(
                            "{face} schema $ref {target:?} at {} does not resolve; \
                             a wrapper probably swallowed the $defs it points at",
                            location(path)
                        ),
                    )),
                    Some(_) => {}
                }
            }

            if strict
                && let Some(format) = numeric_format(map).filter(|f| !PORTABLE_FORMATS.contains(f))
            {
                findings.push((
                    Rule::UnportableFormat,
                    format!(
                        "{face} schema publishes format {format:?} at {}; a strict consumer \
                         knows only {} on a number, so declare the field as i64 with \
                         #[schemars(range(min = .., max = ..))] and read it back with \
                         vibrev_kit::parse_unsigned",
                        location(path),
                        PORTABLE_FORMATS.join(" / "),
                    ),
                ));
            }

            if flag_nullable {
                if has_nullable_type_array(node) {
                    findings.push((
                        Rule::NullableInputBranch,
                        format!(
                            "{face} schema spells optionality as type: {} at {}; \
                             an absent argument belongs out of `required`, not in a null branch",
                            map.get("type").map(ToString::to_string).unwrap_or_default(),
                            location(path)
                        ),
                    ));
                }
                if let Some(index) = null_branch_position(&root, node) {
                    findings.push((
                        Rule::NullableInputBranch,
                        format!(
                            "{face} schema carries a null branch at {}, arm {index}; \
                             an absent argument belongs out of `required`",
                            location(path)
                        ),
                    ));
                }
            }
        });

        report.checked.refs += refs;
        for (rule, detail) in findings {
            report.findings.push(self.finding(tool, rule, detail));
        }
    }

    /// The ratchets are checked in the other direction too: no phantom names,
    /// and sorted so that additions to them stay reviewable. A name is only ever
    /// added to one of these lists, never removed to make a test pass, so the
    /// list itself has to stay legible.
    fn check_ratchets<T: Advertised>(&self, tools: &[T], report: &mut SurfaceReport) {
        let present: Vec<&str> = tools.iter().map(|t| t.advertised().name.as_ref()).collect();

        if let OutputSchemas::Staged(list) = self.output_schemas {
            self.check_ratchet_list("outputSchema", list, &present, report);
        }
        for required in &self.required_properties {
            self.check_ratchet_list(required.name, required.tools, &present, report);
            self.check_required_property(*required, tools, report);
        }
    }

    fn check_ratchet_list(
        &self,
        label: &str,
        list: &[&str],
        present: &[&str],
        report: &mut SurfaceReport,
    ) {
        for name in list {
            if !present.contains(name) {
                report.findings.push(self.surface_finding(
                    Rule::StaleRatchetEntry,
                    format!("the {label} ratchet names {name:?}, which is not on this surface"),
                ));
            }
        }
        if !list.windows(2).all(|pair| pair[0] < pair[1]) {
            report.findings.push(self.surface_finding(
                Rule::UnsortedRatchet,
                format!("keep the {label} ratchet sorted and deduplicated"),
            ));
        }
    }

    fn check_required_property<T: Advertised>(
        &self,
        required: RequiredProperty<'_>,
        tools: &[T],
        report: &mut SurfaceReport,
    ) {
        for tool in tools {
            let tool = tool.advertised();
            let name = tool.name.as_ref();
            if !required.tools.contains(&name) {
                continue;
            }
            let property = required.name;
            let Some(schema) = tool.output_schema.as_ref() else {
                report.findings.push(self.finding(
                    name,
                    Rule::MissingRequiredProperty,
                    format!("owes {property:?} but publishes no outputSchema at all"),
                ));
                continue;
            };
            let declared = schema
                .get("properties")
                .and_then(Value::as_object)
                .is_some_and(|properties| properties.contains_key(property));
            if !declared {
                report.findings.push(self.finding(
                    name,
                    Rule::MissingRequiredProperty,
                    format!("does not declare {property:?} in its outputSchema"),
                ));
                continue;
            }
            let is_required = schema
                .get("required")
                .and_then(Value::as_array)
                .is_some_and(|names| names.iter().any(|item| item.as_str() == Some(property)));
            if !is_required {
                report.findings.push(self.finding(
                    name,
                    Rule::PropertyNotRequired,
                    format!(
                        "declares {property:?} but does not require it, so it can go missing \
                         from the wire exactly when it matters"
                    ),
                ));
            }
        }
    }

    fn finding(&self, tool: &str, rule: Rule, detail: String) -> Finding {
        Finding {
            face: self.face.to_string(),
            tool: Some(tool.to_string()),
            rule,
            detail,
        }
    }

    fn surface_finding(&self, rule: Rule, detail: String) -> Finding {
        Finding {
            face: self.face.to_string(),
            tool: None,
            rule,
            detail,
        }
    }
}

/// The whole contract at its defaults, for an engine with nothing to stage.
pub fn audit(tools: &[ToolDef]) -> SurfaceReport {
    Audit::new("tools").run(tools)
}

fn names<T: Advertised>(tools: &[T]) -> Vec<String> {
    tools
        .iter()
        .map(|tool| tool.advertised().name.to_string())
        .collect()
}

fn location(path: &str) -> &str {
    if path.is_empty() { "the root" } else { path }
}

/// The `format` of a node that describes a number, if it declares one.
///
/// Scoped to numbers because that is where the damage is. A `format` on a string
/// — `uri`, `date-time` — is an annotation a consumer that does not recognise it
/// may ignore, and both engines publish several; a numeric width is what gets
/// the whole declaration rejected.
fn numeric_format(map: &serde_json::Map<String, Value>) -> Option<&str> {
    let format = map.get("format")?.as_str()?;
    let declared = map.get("type")?;
    let numeric = declared.as_str().is_some_and(is_numeric_type)
        || declared
            .as_array()
            .is_some_and(|names| names.iter().filter_map(Value::as_str).any(is_numeric_type));
    numeric.then_some(format)
}

fn is_numeric_type(name: &str) -> bool {
    matches!(name, "integer" | "number")
}

/// The field names of the object a published document describes.
///
/// Deliberately not every `properties` key at every depth: a response carries
/// nested entry types, and one of those having a `total` says nothing about
/// whether the *response* does. Reading the root — following a root `$ref` into
/// the document's own `$defs`, which is the one indirection schemars emits for a
/// newtype or a flattened struct — is what answers "would a client see this key
/// on the payload".
fn root_properties(document: &serde_json::Map<String, Value>) -> BTreeSet<&str> {
    properties_of(resolve_root(document))
}

/// Where a response may honestly keep the answer to "is that all?".
///
/// Two places, and the second is not a loosening — it is the shape a
/// batch-first surface produces. `find_bytes` takes several patterns in one call
/// and answers with one entry per pattern, each paged independently; the page
/// state belongs on the entry, because there is no single page for the call as a
/// whole. A rule that read only the root would demand a field that could not be
/// filled in with anything true.
///
/// The entry level is read more narrowly than the root, because the words carry
/// different weight down there. `next_offset` and `truncated` on an entry can
/// only mean that entry's own paging. `total` cannot: it is an ordinary name for
/// an ordinary count — a basic block's instructions, a segment's bytes — and
/// accepting it one level down would let any list of counted things pass a rule
/// about whether the list itself is complete.
fn page_state(document: &serde_json::Map<String, Value>) -> BTreeSet<&str> {
    /// The two that mean paging wherever they appear.
    const UNAMBIGUOUS: [&str; 2] = ["next_offset", "truncated"];

    let root = resolve_root(document);
    let mut keys = properties_of(root);
    let entries = root
        .get("properties")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|properties| properties.values())
        .filter_map(|property| property.get("items"))
        .filter_map(|items| deref(items, document));
    for entry in entries {
        keys.extend(
            properties_of(entry)
                .into_iter()
                .filter(|key| UNAMBIGUOUS.contains(key)),
        );
    }
    keys
}

fn properties_of(node: &serde_json::Map<String, Value>) -> BTreeSet<&str> {
    node.get("properties")
        .and_then(Value::as_object)
        .map(|properties| properties.keys().map(String::as_str).collect())
        .unwrap_or_default()
}

/// The node a document actually describes: itself, or whatever its root `$ref`
/// points at within the same document.
fn resolve_root(document: &serde_json::Map<String, Value>) -> &serde_json::Map<String, Value> {
    document
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|pointer| follow(document, pointer))
        .and_then(Value::as_object)
        .unwrap_or(document)
}

/// A node with its `$ref` followed, if it carries one.
///
/// `None` when the reference does not resolve — that is [`Rule::DanglingRef`]'s
/// to report, and this rule has nothing to add to it.
fn deref<'a>(
    node: &'a Value,
    document: &'a serde_json::Map<String, Value>,
) -> Option<&'a serde_json::Map<String, Value>> {
    let map = node.as_object()?;
    match map.get("$ref").and_then(Value::as_str) {
        Some(pointer) => follow(document, pointer)?.as_object(),
        None => Some(map),
    }
}

/// Walk a local JSON Pointer — `#/$defs/Name` — through the document.
fn follow<'a>(document: &'a serde_json::Map<String, Value>, pointer: &str) -> Option<&'a Value> {
    let mut node = None;
    for segment in pointer.strip_prefix("#/")?.split('/') {
        node = match node {
            Some(value) => Value::get(value, segment),
            None => document.get(segment),
        };
    }
    node
}

/// Every node of a JSON document, with a JSON Pointer to it.
fn visit(node: &Value, path: String, seen: &mut impl FnMut(&Value, &str)) {
    seen(node, &path);
    match node {
        Value::Object(map) => {
            for (key, child) in map {
                visit(
                    child,
                    format!("{path}/{}", key.replace('~', "~0").replace('/', "~1")),
                    seen,
                );
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                visit(child, format!("{path}/{index}"), seen);
            }
        }
        // Spelled out rather than `_`: the scalars are leaves and have nothing to
        // recurse into, and naming them keeps the exhaustiveness check — a JSON
        // value that gained a composite variant is one this walk would silently
        // stop descending into.
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::{Tool, ToolAnnotations};
    use serde_json::{Map, json};
    use std::sync::Arc;

    fn object(value: Value) -> Arc<Map<String, Value>> {
        Arc::new(value.as_object().expect("object").clone())
    }

    /// A tool that passes everything, so each test can break exactly one thing.
    fn sound(name: &'static str) -> Tool {
        Tool::new(
            name,
            "Does a thing.",
            object(json!({
                "type": "object",
                "properties": {"addr": {"type": "integer"}},
                "required": ["addr"],
            })),
        )
        .with_title(format!("Read {name} out of the database"))
        .with_raw_output_schema(object(json!({
            "type": "object",
            "properties": {"result": {"type": "string"}},
            "required": ["result"],
        })))
        .with_annotations(ToolAnnotations::new().read_only(true))
    }

    fn rules(report: &SurfaceReport) -> Vec<Rule> {
        let mut found: Vec<Rule> = report.findings().iter().map(|f| f.rule).collect();
        found.sort_unstable();
        found.dedup();
        found
    }

    #[test]
    fn a_sound_surface_passes_and_says_what_it_looked_at() {
        let report = Audit::new("native").run(&[sound("decompile"), sound("strings")]);
        assert!(report.is_clean(), "{report}");
        assert_eq!(report.checked().tools, 2);
        assert_eq!(report.checked().input_schemas, 2);
        assert_eq!(report.checked().output_schemas, 2);
    }

    /// The failure a contract test can least afford is passing while checking
    /// nothing, so an empty catalog is itself a finding.
    #[test]
    fn an_empty_catalog_is_not_a_pass() {
        let report = Audit::new("native").run::<Tool>(&[]);
        assert_eq!(rules(&report), vec![Rule::EmptySurface]);
    }

    #[test]
    fn a_missing_read_only_hint_is_caught_on_both_shapes_of_absence() {
        let mut no_annotations = sound("patch");
        no_annotations.annotations = None;
        let mut no_hint = sound("rename");
        no_hint.annotations = Some(ToolAnnotations::default());

        let report = Audit::new("native").run(&[no_annotations, no_hint]);
        assert_eq!(
            rules(&report),
            vec![Rule::MissingAnnotations, Rule::MissingReadOnlyHint]
        );
    }

    #[test]
    fn a_title_that_says_nothing_new_is_a_finding() {
        let mut restates_name = sound("list_funcs");
        restates_name.title = Some("List Funcs".into());
        let mut restates_description = sound("segments");
        restates_description.description = Some("Lists the segments. And more.".into());
        restates_description.title = Some("Lists the segments".into());
        let mut missing = sound("imports");
        missing.title = None;

        let report = Audit::new("native").run(&[restates_name, restates_description, missing]);
        assert_eq!(
            rules(&report),
            vec![
                Rule::MissingTitle,
                Rule::TitleRestatesName,
                Rule::TitleRestatesDescription
            ]
        );
    }

    #[test]
    fn two_tools_may_not_share_a_name_or_a_title() {
        let mut twin = sound("exports");
        twin.title = Some("Read imports out of the database".into());
        let mut other = sound("imports");
        other.title = Some("Read imports out of the database".into());

        let report = Audit::new("native").run(&[sound("exports"), twin, other]);
        assert_eq!(
            rules(&report),
            vec![Rule::DuplicateName, Rule::DuplicateTitle]
        );
    }

    /// Both spellings schemars emits. This is the check that is supposed to go
    /// red the moment an engine with no normalizer is wired up.
    #[test]
    fn an_input_schema_may_not_spell_optional_as_a_null_branch() {
        let mut type_array = sound("disasm");
        type_array.input_schema = object(json!({
            "type": "object",
            "properties": {"max_size": {"type": ["integer", "null"]}},
        }));
        let mut any_of = sound("decompile");
        any_of.input_schema = object(json!({
            "type": "object",
            "$defs": {"Dialect": {"enum": ["c", "rust"]}},
            "properties": {
                "dialect": {"anyOf": [{"$ref": "#/$defs/Dialect"}, {"type": "null"}]},
            },
        }));

        let report = Audit::new("native").run(&[type_array, any_of]);
        assert_eq!(rules(&report), vec![Rule::NullableInputBranch]);
        assert_eq!(report.by_rule(Rule::NullableInputBranch).count(), 2);
        assert!(
            report.findings()[0].detail.contains("/properties/max_size"),
            "a finding has to say where: {}",
            report.findings()[0]
        );
    }

    /// The same shape in an *output* schema is the truth, not a defect: an
    /// `Option` field without `skip_serializing_if` really is emitted as null.
    #[test]
    fn an_output_schema_may_say_a_field_is_null() {
        let mut tool = sound("addr_info");
        tool.output_schema = Some(object(json!({
            "type": "object",
            "properties": {"segment": {"type": ["string", "null"]}},
            "required": ["segment"],
        })));
        assert!(Audit::new("native").run(&[tool]).is_clean());
    }

    /// The two halves of one rule, in the one test where both are visible: the
    /// scan tells an engine to declare an unsigned parameter as `i64`, and
    /// `parse_unsigned` is what an `i64` that arrives out of range does *not*
    /// silently become. The schemas are derived, not hand-written, so this also
    /// pins what schemars actually emits today rather than what a comment
    /// remembers it emitting.
    #[test]
    fn what_the_scan_demands_is_what_the_converter_reads() {
        #[derive(schemars::JsonSchema)]
        #[allow(dead_code)]
        struct Unsigned {
            limit: Option<u32>,
        }
        #[derive(schemars::JsonSchema)]
        #[allow(dead_code)]
        struct Portable {
            #[schemars(range(min = 0, max = 10000))]
            limit: Option<i64>,
        }

        let derived = |schema| {
            let mut tool = sound("strings");
            tool.input_schema = schema;
            // The parameter under test really is a page size, so the fixture
            // owes the other thing a page size costs. Two rules landing on one
            // field is the situation, not an accident of the fixture: `limit`
            // is where the unportable format came from *and* the reason the
            // response has to say where the next page starts.
            let tool = tool.with_raw_output_schema(object(json!({
                "type": "object",
                "properties": {
                    "strings": {"type": "array", "items": {"type": "string"}},
                    "next_offset": {"type": ["integer", "null"]},
                },
                "required": ["strings", "next_offset"],
            })));
            Audit::new("native").run(&[tool])
        };

        let unsigned = derived(crate::schema::input_schema_for::<Unsigned>().expect("schema"));
        assert_eq!(rules(&unsigned), vec![Rule::UnportableFormat]);
        let detail = &unsigned.findings()[0].detail;
        assert!(detail.contains("uint32"), "{detail}");
        assert!(detail.contains("/properties/limit"), "{detail}");
        assert!(detail.contains("parse_unsigned"), "{detail}");

        let portable = derived(crate::schema::input_schema_for::<Portable>().expect("schema"));
        assert!(portable.is_clean(), "{portable}");

        // And the value that field can now carry only reaches a count through
        // the conversion the finding names.
        assert_eq!(crate::parse_unsigned::<usize>(10_000, "limit"), Ok(10_000));
        assert!(crate::parse_unsigned::<usize>(-1, "limit").is_err());
    }

    /// The same width in an *output* schema is not a defect: nothing hands a
    /// response schema to a provider's declaration parser, and a validator that
    /// meets `uint64` is required to ignore what it does not know. Both engines
    /// publish a few hundred of these, so the scope is the difference between a
    /// rule and a rewrite of every response struct.
    #[test]
    fn an_output_schema_may_publish_any_numeric_width() {
        let mut tool = sound("segments");
        tool.output_schema = Some(object(json!({
            "type": "object",
            "properties": {"start": {"type": "integer", "format": "uint64"}},
            "required": ["start"],
        })));
        assert!(Audit::new("native").run(&[tool]).is_clean());
    }

    /// A tool that pages has to say where the next page starts.
    ///
    /// The two engines had five tools between them in exactly this shape — an
    /// `offset` and a `limit` on the way in, a bare list on the way out. The
    /// caller was invited to page and given nothing to page with.
    #[test]
    fn a_tool_that_invites_paging_must_say_where_the_next_page_starts() {
        let paging_input = json!({
            "type": "object",
            "properties": {
                "offset": {"type": "integer"},
                "limit": {"type": "integer"},
            },
        });

        let mut silent = sound("imports");
        silent.input_schema = object(paging_input.clone());
        silent.output_schema = Some(object(json!({
            "type": "object",
            // A total is not enough here: it says more exists without saying
            // where, and computing the offset is what five hand-written copies
            // of this arithmetic got wrong in five different ways.
            "properties": {"imports": {"type": "array"}, "total": {"type": "integer"}},
            "required": ["imports", "total"],
        })));

        let report = Audit::new("native").run(&[silent]);
        assert_eq!(rules(&report), vec![Rule::SilentTruncation]);
        assert!(
            report.findings()[0].detail.contains("next_offset"),
            "a finding has to name the way out: {}",
            report.findings()[0]
        );

        let mut honest = sound("exports");
        honest.input_schema = object(paging_input);
        honest.output_schema = Some(object(json!({
            "type": "object",
            "properties": {
                "exports": {"type": "array"},
                "total": {"type": "integer"},
                "next_offset": {"type": ["integer", "null"]},
            },
            "required": ["exports", "total", "next_offset"],
        })));
        assert!(Audit::new("native").run(&[honest]).is_clean());
    }

    /// A tool that caps a scan without paging it owes a weaker answer.
    ///
    /// There is no second page to ask for, so `next_offset` would be a fiction.
    /// What the caller still cannot work out on their own is whether the cap was
    /// reached, and any of three fields says it.
    #[test]
    fn a_capped_scan_may_say_so_in_any_of_three_ways() {
        let capped = json!({"type": "object", "properties": {"limit": {"type": "integer"}}});
        let answers = |field: &str| {
            let mut tool = sound("find_insns");
            tool.input_schema = object(capped.clone());
            tool.output_schema = Some(object(json!({
                "type": "object",
                "properties": {"matches": {"type": "array"}, field: {"type": "integer"}},
                "required": ["matches", field],
            })));
            Audit::new("native").run(&[tool])
        };

        for field in ["total", "truncated", "next_offset"] {
            assert!(answers(field).is_clean(), "{field} is an honest answer");
        }
        // `count` is the field that looks like an answer and is not: it is the
        // length of the array beside it, so it agrees with the page whether or
        // not the page is everything.
        let report = answers("count");
        assert_eq!(rules(&report), vec![Rule::SilentTruncation]);
    }

    /// A batch tool pages each of its answers, so that is where it says so.
    ///
    /// `find_bytes` takes several patterns in one call and answers with one
    /// entry per pattern. There is no page for the call as a whole, so the root
    /// has nowhere true to put a `next_offset` — demanding one there would be
    /// demanding a fabrication.
    #[test]
    fn a_batch_tool_may_answer_on_each_entry_instead_of_at_the_root() {
        let mut tool = sound("find_bytes");
        tool.input_schema = object(json!({
            "type": "object",
            "properties": {
                "patterns": {"type": "array", "items": {"type": "string"}},
                "offset": {"type": "integer"},
                "limit": {"type": "integer"},
            },
        }));
        tool.output_schema = Some(object(json!({
            "type": "object",
            "$defs": {
                "Entry": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string"},
                        "matches": {"type": "array", "items": {"type": "string"}},
                        "next_offset": {"type": ["integer", "null"]},
                    },
                    "required": ["pattern", "matches", "next_offset"],
                },
            },
            "properties": {"results": {"type": "array", "items": {"$ref": "#/$defs/Entry"}}},
            "required": ["results"],
        })));

        assert!(Audit::new("native").run(&[tool]).is_clean());
    }

    /// The rule reads the response object and its entries, not every type the
    /// document defines.
    ///
    /// A `total` on an entry is not read as an answer, and this is the reason:
    /// `total` is an ordinary name for an ordinary count — here, how many
    /// instructions a basic block has — and it says nothing about whether the
    /// list of blocks around it is complete. `next_offset` and `truncated` are
    /// read at that depth precisely because they cannot mean anything else.
    #[test]
    fn a_total_buried_in_a_nested_type_does_not_answer_for_the_response() {
        let mut tool = sound("basic_blocks");
        tool.input_schema = object(json!({
            "type": "object",
            "properties": {"limit": {"type": "integer"}},
        }));
        tool.output_schema = Some(object(json!({
            "type": "object",
            "$defs": {
                "Block": {
                    "type": "object",
                    "properties": {"total": {"type": "integer"}},
                    "required": ["total"],
                },
            },
            "properties": {"blocks": {"type": "array", "items": {"$ref": "#/$defs/Block"}}},
            "required": ["blocks"],
        })));

        assert_eq!(
            rules(&Audit::new("native").run(&[tool])),
            vec![Rule::SilentTruncation]
        );
    }

    /// A root `$ref` is followed, because that is what schemars emits for a
    /// response that is a newtype over another struct — and a rule that could
    /// not see through it would demand a field that is already there.
    #[test]
    fn a_response_behind_a_root_ref_is_read_through_it() {
        let mut tool = sound("strings");
        tool.input_schema = object(json!({
            "type": "object",
            "properties": {"limit": {"type": "integer"}},
        }));
        tool.output_schema = Some(object(json!({
            "$ref": "#/$defs/StringPage",
            "$defs": {
                "StringPage": {
                    "type": "object",
                    "properties": {"strings": {"type": "array"}, "total": {"type": "integer"}},
                    "required": ["strings", "total"],
                },
            },
        })));

        assert!(Audit::new("native").run(&[tool]).is_clean());
    }

    /// An `offset` that is not a page cursor is left alone.
    ///
    /// `get_bytes` and `patch` take one — an offset *into* the object they were
    /// pointed at — and neither is paging anything. The `limit` is what makes a
    /// tool answerable to this rule, so those never reach it.
    #[test]
    fn an_offset_without_a_limit_is_not_a_page_cursor() {
        let mut tool = sound("get_bytes");
        tool.input_schema = object(json!({
            "type": "object",
            "properties": {"addr": {"type": "integer"}, "offset": {"type": "integer"}},
        }));
        assert!(Audit::new("native").run(&[tool]).is_clean());
    }

    /// A `format` on a string is an annotation, not a width, and this rule has
    /// nothing to say about it.
    #[test]
    fn a_string_format_is_left_alone() {
        let mut tool = sound("open");
        tool.input_schema = object(json!({
            "type": "object",
            "properties": {
                "path": {"type": "string", "format": "uri"},
                "since": {"type": "string", "format": "date-time"},
                "depth": {"type": "integer", "format": "int32"},
            },
        }));
        assert!(Audit::new("native").run(&[tool]).is_clean());
    }

    #[test]
    fn a_ref_must_resolve_inside_the_document_that_carries_it() {
        let mut dangling = sound("callgraph");
        // The supervisor's `{result: …}` wrapper, applied without lifting $defs.
        dangling.output_schema = Some(object(json!({
            "type": "object",
            "properties": {"result": {"$ref": "#/$defs/Node"}},
            "required": ["result"],
        })));
        let mut remote = sound("callers");
        remote.output_schema = Some(object(json!({
            "type": "object",
            "properties": {"result": {"$ref": "https://example.invalid/Node"}},
            "required": ["result"],
        })));

        let report = Audit::new("supervisor").run(&[dangling, remote]);
        assert_eq!(rules(&report), vec![Rule::DanglingRef, Rule::NonLocalRef]);
        assert_eq!(report.checked().refs, 2);
    }

    #[test]
    fn a_resolvable_ref_passes_and_is_counted() {
        let mut tool = sound("callgraph");
        tool.output_schema = Some(object(json!({
            "type": "object",
            "$defs": {"Node": {"type": "string"}},
            "properties": {"result": {"$ref": "#/$defs/Node"}},
            "required": ["result"],
        })));
        let report = Audit::new("native").run(&[tool]);
        assert!(report.is_clean(), "{report}");
        assert_eq!(report.checked().refs, 1);
    }

    #[test]
    fn the_schema_dialect_key_leaks_from_either_face_and_from_any_depth() {
        let mut input = sound("search");
        input.input_schema = object(json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
        }));
        let mut nested_output = sound("strings");
        nested_output.output_schema = Some(object(json!({
            "type": "object",
            "properties": {
                "result": {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "string"},
            },
            "required": ["result"],
        })));

        let report = Audit::new("native").run(&[input, nested_output]);
        assert_eq!(rules(&report), vec![Rule::SchemaDialectLeak]);
        assert!(
            report.findings()[1].detail.contains("/properties/result"),
            "{}",
            report.findings()[1]
        );
    }

    #[test]
    fn output_schemas_are_staged_by_the_engines_own_ratchet() {
        let mut converted = sound("decompile");
        let mut unconverted = sound("aaa_not_yet");
        converted.output_schema = None;
        unconverted.output_schema = None;

        let staged = Audit::new("native")
            .output_schemas(OutputSchemas::Staged(&["decompile"]))
            .run(&[converted.clone(), unconverted.clone()]);
        assert_eq!(rules(&staged), vec![Rule::MissingOutputSchema]);
        assert_eq!(
            staged.findings()[0].tool.as_deref(),
            Some("decompile"),
            "only the converted tool is on the ratchet"
        );

        let total = Audit::new("native").run(&[converted, unconverted]);
        assert_eq!(total.by_rule(Rule::MissingOutputSchema).count(), 2);
    }

    #[test]
    fn a_ratchet_that_has_gone_stale_or_unsorted_is_itself_a_finding() {
        let report = Audit::new("native")
            .output_schemas(OutputSchemas::Staged(&["strings", "decompile"]))
            .run(&[sound("decompile")]);
        assert_eq!(
            rules(&report),
            vec![Rule::StaleRatchetEntry, Rule::UnsortedRatchet]
        );
    }

    /// The required-property convention in the shape kit can carry: the
    /// mechanism, driven by the engine's list. Declaring the property is not
    /// enough — it has to be `required`.
    #[test]
    fn a_declared_but_optional_property_does_not_satisfy_the_requirement() {
        let mut optional = sound("list_funcs");
        optional.output_schema = Some(object(json!({
            "type": "object",
            "properties": {"analysis_coverage": {"type": "object"}, "total": {"type": "integer"}},
            "required": ["total"],
        })));
        let mut absent = sound("strings");
        absent.output_schema = Some(object(json!({
            "type": "object",
            "properties": {"total": {"type": "integer"}},
            "required": ["total"],
        })));
        let untouched = sound("segments");

        let report = Audit::new("native")
            .require_output_property("analysis_coverage", &["list_funcs", "strings"])
            .run(&[optional, absent, untouched]);

        assert_eq!(
            rules(&report),
            vec![Rule::MissingRequiredProperty, Rule::PropertyNotRequired]
        );
        assert!(
            report
                .by_rule(Rule::MissingRequiredProperty)
                .all(|f| f.tool.as_deref() == Some("strings")),
            "segments owes nothing: {report}"
        );
    }

    #[test]
    fn an_unstable_catalog_order_is_caught_by_rebuilding_it() {
        let mut round = 0usize;
        let report = Audit::new("native").run_repeated(|| {
            round += 1;
            if round.is_multiple_of(2) {
                vec![sound("strings"), sound("decompile")]
            } else {
                vec![sound("decompile"), sound("strings")]
            }
        });
        assert_eq!(rules(&report), vec![Rule::UnstableOrder]);
        assert!(report.findings()[0].detail.contains("index 0"));
    }

    #[test]
    fn a_stable_catalog_survives_rebuilding() {
        let report =
            Audit::new("native").run_repeated(|| vec![sound("decompile"), sound("strings")]);
        assert!(report.is_clean(), "{report}");
        assert_eq!(report.checked().tools, 2, "the audit still ran once");
    }

    #[test]
    fn several_faces_fail_together() {
        let mut native = Audit::new("native").run(&[sound("decompile")]);
        let mut broken = sound("idb_open");
        broken.annotations = None;
        native.merge(Audit::new("supervisor").run(&[broken]));

        assert_eq!(native.checked().tools, 2);
        assert_eq!(native.findings().len(), 1);
        assert_eq!(native.findings()[0].face, "supervisor");
        assert!(
            format!("{native}").contains("supervisor/idb_open"),
            "the report has to name the face: {native}"
        );
    }
}
