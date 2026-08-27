//! Turn tool results into something a human — or an agent reading a terminal —
//! can consume without wading through JSON nesting.
//!
//! Three rules, inherited from `ida_rpc`'s CLI:
//!
//! 1. A text-bearing key (`c_code`, `listing`, …) prints as a bare string, so
//!    decompiler output can be piped straight into a file or a diff.
//! 2. A list of objects prints as a width-aligned table.
//! 3. An object holding exactly one list plus bookkeeping keys prints as a header
//!    line and that table — which removes most `.result.xxx` nesting noise.
//!
//! # What counts as bookkeeping
//!
//! Rules 1 and 3 both need to decide whether the *other* keys of an object are
//! incidental to it. A name list — `count`, `total`, `offset`, and a handful
//! more — cannot answer that for long, because a list only knows the conventions
//! that existed when it was written and rots against every one invented after.
//! `analysis_coverage` is the standing example: a tool returning a global
//! statistic is expected to publish it, no name list can anticipate that, and an
//! unrecognised sibling drops the whole payload out of table rendering into
//! `pretty()`. Two conventions cancelling each other, visible only as "the
//! readable output stopped happening".
//!
//! [`is_bookkeeping`] asks a structural question instead — is this small enough
//! that a header line can carry it? — so a convention invented next month works
//! without an edit here. Binary Ninja's engine found the `analysis_coverage`
//! case; it is the second engine to build on this crate and the first to be
//! written against it as an external contract.

use serde_json::{Map, Value};

const TEXT_KEYS: &[&str] = &["c_code", "listing", "hexdump", "content", "code", "source"];

/// Longest single-line string still treated as incidental rather than content.
const BOOKKEEPING_STRING_MAX: usize = 96;
/// Most fields a nested object may have and still fit on a header line.
const BOOKKEEPING_OBJECT_MAX: usize = 8;

/// Is this value small enough to ride along on a header line?
///
/// Scalars always. A string only while it is short and single-line — a long or
/// multi-line one is content, and summarising content is how a renderer loses
/// it. An object only while it is flat and small, which is exactly the shape of
/// `analysis_coverage` and of every completeness/paging block like it.
fn is_bookkeeping(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => true,
        Value::String(s) => s.len() <= BOOKKEEPING_STRING_MAX && !s.contains('\n'),
        Value::Object(map) => {
            map.len() <= BOOKKEEPING_OBJECT_MAX
                && map.values().all(|v| {
                    matches!(
                        v,
                        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
                    ) && is_bookkeeping(v)
                })
        }
        Value::Array(_) => false,
    }
}

fn bookkeeping_pair(key: &str, value: &Value) -> String {
    match value {
        Value::String(s) => format!("{key}={s}"),
        other => format!("{key}={other}"),
    }
}

pub fn render(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Array(items) => render_array(items),
        Value::Object(map) => render_object(map),
        other => other.to_string(),
    }
}

fn render_object(map: &Map<String, Value>) -> String {
    // Rule 1 — a text payload prints as itself.
    //
    // Requiring `map.len() == 1` would collapse the rule the moment a payload
    // grew a sibling: a function name, an address or an `analysis_coverage`
    // block next to `c_code` would send the whole thing to `pretty()`, and the
    // pseudocode would come back as one JSON string with its newlines escaped.
    // That is precisely the failure `Rendered<T>` exists to prevent, reached by
    // a different route — and it would make "your output is readable" and "your
    // output declares how complete it is" mutually exclusive, which is not a
    // choice a tool author should have to make.
    //
    // So siblings are allowed as long as they are bookkeeping, and they are
    // reported on a trailing line rather than dropped: a caveat about
    // incompleteness that the text form silently omitted would be worse than
    // ugly. A tool that publishes only the text still prints only the text, so
    // piping into a file or a diff is unaffected.
    let texts: Vec<(&String, &String)> = map
        .iter()
        .filter_map(|(k, v)| match v {
            Value::String(s) if TEXT_KEYS.contains(&k.as_str()) => Some((k, s)),
            _ => None,
        })
        .collect();
    if let [(text_key, text)] = texts.as_slice() {
        let rest: Vec<String> = map
            .iter()
            .filter(|(k, _)| k != text_key)
            .filter(|(_, v)| is_bookkeeping(v))
            .map(|(k, v)| bookkeeping_pair(k, v))
            .collect();
        if rest.len() == map.len() - 1 {
            if rest.is_empty() {
                return (*text).clone();
            }
            return format!("{text}\n\n[{}]", rest.join(", "));
        }
    }

    // Rule 3 — exactly one list, everything else bookkeeping.
    let lists: Vec<(&String, &Vec<Value>)> = map
        .iter()
        .filter_map(|(k, v)| v.as_array().map(|a| (k, a)))
        .collect();
    if let [(key, items)] = lists.as_slice() {
        let rest: Vec<(&String, &Value)> = map.iter().filter(|(k, _)| k != key).collect();
        if rest.iter().all(|(_, v)| is_bookkeeping(v)) {
            let mut header = format!("{key} ({} items", items.len());
            if let Some(total) = map.get("total") {
                header.push_str(&format!(", total={total}"));
            }
            if map.get("truncated") == Some(&Value::Bool(true)) {
                header.push_str(", truncated");
            }
            // Everything else the object carries, named. The old rule listed
            // seven blessed keys and printed two of them, so `error_count` was
            // both required to be present and then thrown away.
            for (k, v) in &rest {
                if k.as_str() == "total" || k.as_str() == "truncated" {
                    continue;
                }
                header.push_str(&format!(", {}", bookkeeping_pair(k, v)));
            }
            header.push_str("):");
            return format!("{header}\n{}", render_array(items));
        }
    }

    pretty(&Value::Object(map.clone()))
}

fn render_array(items: &[Value]) -> String {
    if items.is_empty() {
        return "(空)".to_owned();
    }
    let rows: Vec<&Map<String, Value>> = items.iter().filter_map(Value::as_object).collect();
    if rows.len() != items.len() {
        // Not uniformly objects — a plain list reads better than a ragged table.
        return items
            .iter()
            .map(|v| match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .collect::<Vec<_>>()
            .join("\n");
    }

    // Column order: first appearance across all rows, deduplicated.
    let mut columns: Vec<&str> = Vec::new();
    for row in &rows {
        for k in row.keys() {
            if !columns.contains(&k.as_str()) {
                columns.push(k);
            }
        }
    }

    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| columns.iter().map(|c| scalar(row.get(*c))).collect())
        .collect();

    let widths: Vec<usize> = columns
        .iter()
        .enumerate()
        .map(|(i, c)| {
            cells
                .iter()
                .map(|r| r[i].chars().count())
                .chain(std::iter::once(c.chars().count()))
                .max()
                .unwrap_or(0)
        })
        .collect();

    let mut out = String::new();
    out.push_str(&join_padded(
        &columns.iter().map(|c| (*c).to_owned()).collect::<Vec<_>>(),
        &widths,
    ));
    out.push('\n');
    out.push_str(
        &widths
            .iter()
            .map(|w| "-".repeat(*w))
            .collect::<Vec<_>>()
            .join("  "),
    );
    for row in &cells {
        out.push('\n');
        out.push_str(&join_padded(row, &widths));
    }
    out
}

fn join_padded(cells: &[String], widths: &[usize]) -> String {
    cells
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let pad = widths[i].saturating_sub(c.chars().count());
            let mut s = c.clone();
            if i + 1 < cells.len() {
                s.push_str(&" ".repeat(pad));
            }
            s
        })
        .collect::<Vec<_>>()
        .join("  ")
        .trim_end()
        .to_owned()
}

fn scalar(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

pub fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
}

#[cfg(test)]
mod tests {
    use super::render;
    use serde_json::json;

    #[test]
    fn decompiler_output_prints_bare() {
        let v = json!({ "c_code": "int main() {\n  return 0;\n}" });
        assert_eq!(render(&v), "int main() {\n  return 0;\n}");
    }

    /// Declaring coverage and staying readable are not mutually exclusive: the
    /// bare-text rule tolerates bookkeeping siblings, so a decompiler tool that
    /// also says how complete its analysis was still prints pseudocode rather
    /// than escaped JSON.
    #[test]
    fn a_text_payload_may_carry_bookkeeping_and_stay_readable() {
        let v = json!({
            "c_code": "int main() {\n  return 0;\n}",
            "analysis_coverage": { "state": "partial", "auto_is_ok": false },
        });
        let out = render(&v);
        assert!(out.starts_with("int main() {\n  return 0;\n}"), "{out}");
        // …and the caveat is *shown*, not quietly dropped, which would be the
        // other way to keep the text readable and the worse one.
        assert!(out.contains("analysis_coverage"), "{out}");
        assert!(out.contains("partial"), "{out}");
    }

    /// A substantial sibling is content, not bookkeeping, and a renderer that
    /// summarised it on one line would be losing it.
    #[test]
    fn a_second_body_of_text_is_not_bookkeeping() {
        let v = json!({
            "c_code": "int main() { return 0; }",
            "listing": "push rbp\nmov rbp, rsp",
        });
        assert!(render(&v).starts_with('{'), "expected the JSON fallback");
    }

    #[test]
    fn one_list_plus_bookkeeping_becomes_a_titled_table() {
        let v = json!({
            "functions": [{"name": "main", "addr": "0x1000"}, {"name": "init", "addr": "0x1040"}],
            "total": 1523,
        });
        let out = render(&v);
        assert!(out.starts_with("functions (2 items, total=1523):"));
        assert!(out.contains("name"));
        assert!(out.contains("0x1040"));
    }

    /// The bug Binary Ninja's engine reported: a fixed `META_KEYS` list never
    /// learned about `analysis_coverage`, so every tool publishing one lost its
    /// table. Asserted structurally — a name nobody has thought of yet must
    /// work too.
    #[test]
    fn a_coverage_block_does_not_cost_a_tool_its_table() {
        let v = json!({
            "functions": [{"name": "main", "addr": "0x1000"}],
            "total": 161,
            "analysis_coverage": { "state": "complete", "auto_is_ok": true },
            "a_convention_invented_next_month": 7,
        });
        let out = render(&v);
        assert!(out.starts_with("functions (1 items, total=161"), "{out}");
        assert!(out.contains("analysis_coverage"), "{out}");
        assert!(out.contains("a_convention_invented_next_month=7"), "{out}");
        assert!(out.contains("0x1000"), "the table is still a table:\n{out}");
    }

    /// The header now names everything it kept, rather than requiring a key to
    /// be on a list and then printing only two of them.
    #[test]
    fn bookkeeping_the_header_used_to_swallow_is_shown() {
        let v = json!({ "items": [{"a": 1}], "error_count": 3 });
        assert!(render(&v).starts_with("items (1 items, error_count=3):"));
    }

    #[test]
    fn ragged_rows_still_share_a_column_set() {
        let v = json!([{"a": 1}, {"b": 2}]);
        let out = render(&v);
        assert!(out.lines().next().unwrap().contains('a'));
        assert!(out.lines().next().unwrap().contains('b'));
    }
}
