//! What `doctor` and `engine list` print.
//!
//! One [`EngineReport`] per engine feeds both the aligned table and the `--json`
//! document, so the two can never disagree about what was found.

use camino::Utf8PathBuf;
use comfy_table::{Cell, Color, ContentArrangement, Table, presets::NOTHING};
use serde_json::{Value, json};

use crate::config::Paths;
use crate::discover::{Located, Outcome};
use crate::engine::Engine;
use crate::probe::Probe;

#[derive(Debug)]
pub struct EngineReport {
    pub engine: &'static Engine,
    pub located: Option<Located>,
    /// `None` when the probe was skipped (`--no-probe`) or the binary is missing.
    pub probe: Option<Probe>,
    pub config_error: Option<(Utf8PathBuf, String)>,
}

/// What the leading mark means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Found and it told us who it is.
    Ok,
    /// Binary is there but we did not ask (`--no-probe`).
    Present,
    /// Binary is there and the handshake did not work.
    Unreachable,
    /// Nothing found at any of the four levels.
    Missing,
    /// `config.toml` points at something unusable.
    ConfigError,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Present => "present",
            Status::Unreachable => "unreachable",
            Status::Missing => "missing",
            Status::ConfigError => "config-error",
        }
    }

    fn mark(self) -> (&'static str, Option<Color>) {
        match self {
            Status::Ok => ("✓", Some(Color::Green)),
            Status::Present => ("•", None),
            Status::Unreachable | Status::ConfigError => ("!", Some(Color::Yellow)),
            Status::Missing => ("✗", Some(Color::Red)),
        }
    }
}

impl EngineReport {
    pub fn new(engine: &'static Engine, outcome: Outcome) -> Self {
        let (located, config_error) = match outcome {
            Outcome::Found(l) => (Some(l), None),
            Outcome::Missing => (None, None),
            Outcome::ConfigBroken { path, reason } => (None, Some((path, reason))),
        };
        Self {
            engine,
            located,
            probe: None,
            config_error,
        }
    }

    pub fn status(&self) -> Status {
        if self.config_error.is_some() {
            return Status::ConfigError;
        }
        match (&self.located, &self.probe) {
            (None, _) => Status::Missing,
            (Some(_), None) => Status::Present,
            (Some(_), Some(Probe::Ok(_))) => Status::Ok,
            (Some(_), Some(_)) => Status::Unreachable,
        }
    }

    pub fn found(&self) -> bool {
        self.located.is_some()
    }

    /// Middle column: the MCP identity when we have it, otherwise why we do not.
    fn identity_cell(&self) -> String {
        match self.status() {
            Status::Ok => self
                .probe
                .as_ref()
                .and_then(Probe::identity)
                .map(|i| i.display())
                .unwrap_or_default(),
            Status::Present => format!("{}（未握手）", self.engine.bin),
            Status::Unreachable => format!("{}（身份未知）", self.engine.bin),
            Status::Missing => format!("未找到 {}", self.engine.bin),
            Status::ConfigError => "配置指向的文件不可用".to_owned(),
        }
    }

    fn note(&self) -> String {
        if let Some((_, reason)) = &self.config_error {
            return format!("config.toml: {reason}");
        }
        // Nothing for a missing engine: `doctor` prints its install block a few
        // lines below, and a "see below" pointer only widens the table.
        match &self.probe {
            Some(p) => p.note().unwrap_or_default(),
            None => String::new(),
        }
    }

    /// Absolute paths, not `~`-abbreviated: this output is for machines.
    pub fn to_json(&self, with_install: bool) -> Value {
        let mut o = serde_json::Map::new();
        o.insert("id".into(), self.engine.id.into());
        o.insert("binary".into(), self.engine.bin.into());
        o.insert("status".into(), self.status().as_str().into());

        if let Some(l) = &self.located {
            o.insert("path".into(), l.path.as_str().into());
            o.insert("origin".into(), l.origin.as_str().into());
            o.insert("mcpArgs".into(), json!(l.mcp_args));
        }
        if let Some((path, reason)) = &self.config_error {
            o.insert("configuredPath".into(), path.as_str().into());
            o.insert("error".into(), reason.as_str().into());
        }
        match &self.probe {
            Some(Probe::Ok(i)) => {
                o.insert(
                    "serverInfo".into(),
                    json!({
                        "name": i.name,
                        "version": i.version,
                        "protocolVersion": i.protocol,
                    }),
                );
            }
            Some(other) => {
                if let Some(note) = other.note() {
                    o.insert("error".into(), note.into());
                }
            }
            None => {}
        }
        if with_install && self.located.is_none() {
            o.insert("install".into(), json!(self.engine.install));
        }
        Value::Object(o)
    }
}

/// Spaces between columns.
const COLUMN_GAP: u16 = 2;

/// The aligned block: mark, id, identity, origin, note.
pub fn table(reports: &[&EngineReport], paths: &Paths, color: bool) -> String {
    let mut table = Table::new();
    table
        .load_preset(NOTHING)
        .set_content_arrangement(ContentArrangement::Disabled);

    for r in reports {
        let (glyph, fg) = r.status().mark();
        let mut mark = Cell::new(glyph);
        if color && let Some(fg) = fg {
            mark = mark.fg(fg);
        }
        let origin = match &r.located {
            Some(l) => l.origin.label(paths, &l.path),
            None => String::new(),
        };
        table.add_row(vec![
            mark,
            Cell::new(r.engine.id),
            Cell::new(r.identity_cell()),
            Cell::new(origin),
            Cell::new(r.note()),
        ]);
    }

    // Pad on the right only: the caller indents the block, so a left pad on the
    // first column would just make the mark column look misaligned with it.
    for column in table.column_iter_mut() {
        column.set_padding((0, COLUMN_GAP));
    }

    // Empty note cells would otherwise leave that padding as ragged whitespace.
    table
        .to_string()
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
}
