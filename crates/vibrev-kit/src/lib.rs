//! Shared runtime for VibRev engines.
//!
//! Each engine is a complete MCP server that also carries its own CLI.
//! This crate holds everything that would otherwise be reimplemented per engine:
//! JSON Schema -> clap construction, argument mapping back to tool arguments, and
//! the output renderer. Engines get their command tree from `vibrev-tool-macros`;
//! the conventions enforced here are what keep the three engines feeling alike.
//!
//! [`token`] has a second kind of consumer. The installer is not an engine, but it
//! writes a file the engines read, and a format agreed on by two programs that
//! cannot see each other's source is a format that drifts. So the rule for this
//! crate is not "engines only" but *anything two VibRev programs have to agree on*.

pub mod cli;
pub mod contract;
pub mod decorate;
pub mod output;
pub mod page;
pub mod policy;
pub mod render;
pub mod schema;
pub mod session;
pub mod tasks;
pub mod token;
/// The HTTP listener, behind the `http` feature.
///
/// Gated because a stdio-only engine — and the installer, which speaks no
/// protocol at all — should not compile axum to get [`schema`] and [`policy`].
#[cfg(feature = "http")]
pub mod transport;

use std::borrow::Cow;
use std::fmt;

use rmcp::{
    ErrorData,
    handler::server::tool::IntoCallToolResult,
    model::{CallToolResponse, CallToolResult, ContentBlock},
};
use serde::Serialize;
use serde_json::Value;

/// One tool call's answer, in the shape the CLI front end consumes.
///
/// The macro builds this by running the tool's return value through
/// [`IntoCallToolResult`] — the *same* trait rmcp's `ToolRouter` calls on the MCP
/// path — and then reading the resulting `CallToolResult`. So [`text`](Self::text)
/// is not a second rendering of the payload that happens to agree with `content`:
/// it is literally the bytes `content[0]` carries. The two front ends cannot
/// disagree because there is only one producer.
///
/// It also carries [`is_error`](Self::is_error), which is why the CLI can be
/// derived from engines that report tool failures the way MCP specifies —
/// `isError: true` on a *successful* JSON-RPC response, not a JSON-RPC error.
/// A `Result<T, ErrorData>` cannot express that distinction, so an outcome type
/// that dropped it would force every such engine to either lie about failures or
/// stay off the derived CLI entirely.
#[derive(Debug, Clone)]
pub struct ToolOutcome {
    /// Concatenation of the text content blocks, `\n`-joined. For the
    /// single-block results every VibRev engine produces this is `content[0]`
    /// byte for byte.
    pub text: String,
    /// `structuredContent`, when the tool published one.
    pub structured: Option<Value>,
    /// The tool ran and reported failure (`isError: true`). Distinct from the
    /// `Err` arm of the call, which is a JSON-RPC/transport-level failure.
    pub is_error: bool,
}

impl ToolOutcome {
    /// Read an outcome out of whatever the tool returned.
    ///
    /// The two non-`Complete` arms have no CLI representation and are reported
    /// rather than flattened: an elicitation the CLI cannot answer, or a task
    /// handle it cannot poll, would otherwise print as an empty success.
    pub fn from_response(response: CallToolResponse) -> Result<Self, ErrorData> {
        match response {
            CallToolResponse::Complete(result) => Ok(Self::from_result(result)),
            CallToolResponse::InputRequired(_) => Err(ErrorData::internal_error(
                "this tool requires interactive input (elicitation), which the CLI cannot answer; call it from an MCP client",
                None,
            )),
            CallToolResponse::Task(_) => Err(ErrorData::internal_error(
                "this tool returned a background task handle, which the CLI cannot poll; call it from an MCP client",
                None,
            )),
            // `CallToolResponse` is #[non_exhaustive]; a response shape rmcp adds
            // later is one this CLI has never rendered, so say so rather than
            // guess at a text form for it.
            other => Err(ErrorData::internal_error(
                format!("the CLI cannot render this tool response: {other:?}"),
                None,
            )),
        }
    }

    pub fn from_result(result: CallToolResult) -> Self {
        let text = result
            .content
            .iter()
            .filter_map(|block| block.as_text())
            .map(|text| text.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        Self {
            text,
            structured: result.structured_content,
            is_error: result.is_error == Some(true),
        }
    }

    /// What `--json` prints: the structured payload, or the text for a tool that
    /// published none (error results, mostly).
    pub fn json_text(&self) -> String {
        match &self.structured {
            Some(value) => render::pretty(value),
            None => self.text.clone(),
        }
    }
}

/// A tool result that ships both a typed payload and a *readable* text rendering.
///
/// rmcp's own [`Json<T>`](rmcp::handler::server::wrapper::Json) sets `structuredContent`
/// but also overwrites `content` with the compact serialization, so a decompiler tool
/// would hand the model `{"c_code":"int main(void) {\n ..."}` — escaped JSON where
/// pseudocode should be. `Rendered<T>` keeps `structuredContent` and puts the same text
/// the CLI would print into `content`, so the two front ends agree by construction.
///
/// Tools that genuinely want the raw JSON in `content` can still return `Json<T>`.
///
/// # What `T` should look like
///
/// The renderer recognises two payload shapes (see [`render`](crate::render)) and
/// falls back to pretty JSON for anything else, so the shape of `T` is what
/// decides whether a result reads well. This is a design constraint on the
/// payload type and it had never been written down:
///
/// * **A text payload.** One field named `c_code`/`listing`/`hexdump`/`content`/
///   `code`/`source` carrying the text, and beside it only *small* fields —
///   scalars, or a flat object such as an `analysis_coverage` block. Those print
///   on a trailing line. A second body of text is not bookkeeping, and two of
///   them send the payload to JSON, because summarising one of them onto a
///   header line would lose it.
/// * **A listing.** Exactly one array field, everything else small. The array
///   becomes a table and the rest becomes its header line.
///
/// So: *one* array, or *one* body of text, is what makes a payload readable. Two
/// lists — or a list next to prose — is a payload that wants to be two tools.
/// Adding metadata is safe; adding a second payload is not.
pub struct Rendered<T>(pub T);

impl<T: schemars::JsonSchema> schemars::JsonSchema for Rendered<T> {
    fn schema_name() -> Cow<'static, str> {
        T::schema_name()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        T::json_schema(generator)
    }
}

impl<T: Serialize + schemars::JsonSchema + 'static> IntoCallToolResult for Rendered<T> {
    fn into_call_tool_result(self) -> Result<CallToolResponse, ErrorData> {
        let value = serde_json::to_value(self.0)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        let text = render::render(&value);
        let mut result = CallToolResult::structured(value);
        result.content = vec![ContentBlock::text(text)];
        Ok(result.into())
    }
}

/// CLI hints declared at the tool site. Deliberately *not* part of the MCP `_meta`:
/// the CLI is built in the same process from the same binary, so these never need
/// to be serialized or version-negotiated.
#[derive(Debug, Clone, Copy)]
pub struct CliHints {
    /// Parameter names rendered as positional arguments instead of `--flags`.
    pub positional: &'static [&'static str],
    /// Parameter names that accept `184` / `0xb8` / `0b1011`.
    pub int_args: &'static [&'static str],
    /// Whether this tool appears in the CLI at all.
    pub enabled: bool,
    /// Whether this tool reads the engine's session.
    ///
    /// `true` for almost everything a reverse-engineering engine does, and the
    /// default for that reason. The exceptions are real though: `tool_help`,
    /// `tool_catalog` and `int_convert` answer out of the catalog or out of pure
    /// arithmetic, and demanding `--idb` before printing a tool's documentation
    /// is the sort of requirement that reads as a bug. Declared at the tool
    /// rather than kept as a list somewhere, for the usual reason.
    pub needs_session: bool,
}

/// A tool plus everything the CLI front end needs to expose it.
#[derive(Debug, Clone)]
pub struct ToolDef {
    pub tool: rmcp::model::Tool,
    pub cli: CliHints,
    /// Extension group; `Some(..)` means hidden unless explicitly requested.
    pub ext: Option<&'static str>,
}

impl ToolDef {
    pub fn name(&self) -> &str {
        &self.tool.name
    }
}

/// Anything a client would see in a `tools/list` answer.
///
/// Engines advertise from more than one place — a derived catalog of [`ToolDef`],
/// and hand-built [`Tool`](rmcp::model::Tool)s for session lifecycle — and every
/// face owes the same contract and obeys the same policy. Both
/// [`contract`](crate::contract) and [`policy`](crate::policy) read catalogs
/// through this rather than each inventing its own, so an engine implements
/// nothing to be covered by both.
pub trait Advertised {
    fn advertised(&self) -> &rmcp::model::Tool;
}

impl Advertised for rmcp::model::Tool {
    fn advertised(&self) -> &rmcp::model::Tool {
        self
    }
}

impl Advertised for ToolDef {
    fn advertised(&self) -> &rmcp::model::Tool {
        &self.tool
    }
}

impl<T: Advertised + ?Sized> Advertised for &T {
    fn advertised(&self) -> &rmcp::model::Tool {
        (**self).advertised()
    }
}

/// Build an [`rmcp::model::Implementation`] from the *calling* crate's identity.
///
/// `Implementation::from_build_env()` reads correctly but expands `env!()` inside
/// rmcp, so a server that relies on it reports `rmcp` as its own name. That is the
/// quiet version of one server impersonating another, and it is the default, so
/// every engine must opt out of it explicitly.
#[macro_export]
macro_rules! engine_identity {
    () => {
        ::rmcp::model::Implementation::new(
            ::core::env!("CARGO_PKG_NAME"),
            ::core::env!("CARGO_PKG_VERSION"),
        )
    };
}

/// Accepts decimal, `0x` hex and `0b` binary, with an optional leading `-`.
///
/// Addresses are the single most common CLI argument in this domain and agents
/// write them in whichever base the disassembler last showed them.
pub fn parse_int(s: &str) -> Result<i64, String> {
    let t = s.trim();
    let (neg, t) = match t.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, t),
    };
    let parsed = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        i64::from_str_radix(h, 16)
    } else if let Some(b) = t.strip_prefix("0b").or_else(|| t.strip_prefix("0B")) {
        i64::from_str_radix(b, 2)
    } else {
        t.parse::<i64>()
    };
    parsed
        .map(|v| if neg { -v } else { v })
        .map_err(|_| format!("{s:?} is not a valid integer (use 184 or 0xb8)"))
}

/// A wire value that will not fit the Rust type the tool works in.
///
/// A type rather than a formatted message, for the reason
/// [`token::TokenError`](token::TokenError) is one: the sentence a user reads
/// belongs to the engine, which knows what language it speaks and which of its
/// own error variants this is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutOfRange {
    /// The parameter, spelled as it is on the wire.
    pub field: String,
    pub value: i64,
    /// The Rust type it could not become — `usize`, `u64`.
    pub expected: &'static str,
}

impl fmt::Display for OutOfRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}) is out of range for {}",
            self.field, self.value, self.expected
        )
    }
}

impl std::error::Error for OutOfRange {}

/// Convert a wire integer into the unsigned type the tool actually counts in.
///
/// This is the other half of [`contract::Rule::UnportableFormat`]. That rule
/// bans `uint*` from a published `inputSchema`, so an unsigned quantity travels
/// as `i64` with `#[schemars(range(min = 0, ...))]` — and a schema bound is
/// *advice*. Nothing in serde enforces `minimum`, so a client that does not read
/// the schema still hands over `-1`, and `-1i64 as usize` is
/// 18446744073709551615: an empty page, a zero-length read, an answer that looks
/// like an answer. Refusing is the only behaviour that cannot be mistaken for
/// working, so the way back from the wire is a conversion, not a cast.
///
/// [`parse_int`] is the same story on the CLI side: every integer argument
/// arrives as an `i64` there too, from a string a person typed.
pub fn parse_unsigned<T: TryFrom<i64>>(value: i64, field: &str) -> Result<T, OutOfRange> {
    T::try_from(value).map_err(|_| OutOfRange {
        field: field.to_string(),
        value,
        expected: std::any::type_name::<T>(),
    })
}

/// [`parse_unsigned`] for a parameter the caller may leave out.
pub fn parse_optional_unsigned<T: TryFrom<i64>>(
    value: Option<i64>,
    field: &str,
) -> Result<Option<T>, OutOfRange> {
    match value {
        Some(value) => parse_unsigned(value, field).map(Some),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_int, parse_optional_unsigned, parse_unsigned};

    #[test]
    fn a_negative_wire_value_is_refused_rather_than_wrapped() {
        assert_eq!(parse_unsigned::<usize>(7, "limit"), Ok(7));
        let refused = parse_unsigned::<usize>(-1, "offset").expect_err("negative offset");
        assert_eq!(refused.to_string(), "offset (-1) is out of range for usize");
        // The cast this exists to prevent, for the record.
        assert_eq!(-1i64 as usize, usize::MAX);
    }

    #[test]
    fn a_value_too_wide_for_the_destination_is_refused_too() {
        assert!(parse_unsigned::<u32>(i64::from(u32::MAX) + 1, "length").is_err());
        assert_eq!(
            parse_unsigned::<u32>(i64::from(u32::MAX), "length"),
            Ok(u32::MAX)
        );
    }

    #[test]
    fn an_absent_parameter_stays_absent() {
        assert_eq!(
            parse_optional_unsigned::<u64>(None, "timeout_secs"),
            Ok(None)
        );
        assert_eq!(
            parse_optional_unsigned::<u64>(Some(60), "timeout_secs"),
            Ok(Some(60))
        );
        assert!(parse_optional_unsigned::<u64>(Some(-60), "timeout_secs").is_err());
    }

    #[test]
    fn integers_accept_every_base_an_agent_might_use() {
        assert_eq!(parse_int("184"), Ok(184));
        assert_eq!(parse_int("0xb8"), Ok(184));
        assert_eq!(parse_int("0XB8"), Ok(184));
        assert_eq!(parse_int("0b1011"), Ok(11));
        assert_eq!(parse_int("-0x10"), Ok(-16));
        assert!(parse_int("main").is_err());
    }
}
