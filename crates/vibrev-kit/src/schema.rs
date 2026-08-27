//! The JSON Schema vocabulary every face in this workspace has to speak.
//!
//! schemars writes `Option<T>` in more than one shape, and puts anything with a
//! name behind a `$ref`, so "what does this parameter actually accept" is a
//! question three separate places have to answer identically: the CLI builder
//! in [`cli`](crate::cli), `ida-headless-mcp`'s normalizer at its MCP exit, and
//! the contract scan in [`contract`](crate::contract).
//!
//! Both halves live here. The *reading* half — [`deref`], [`effective`],
//! [`is_null_branch`], [`types_of`] — says what a schema node means. The
//! *rewriting* half — [`normalize_input`], [`strip_dialect`] — says what this
//! workspace publishes instead. They are written against each other on purpose:
//! the auditor flags exactly the shapes the normalizer removes, so a face that
//! skipped normalization is a failing test rather than a quiet difference
//! between two engines' `inputSchema`.
//!
//! # Where this runs
//!
//! At the point a `Tool` is *built*, not at the point it is served.
//! [`input_schema_for`] and [`output_schema_for`] are what `#[vibrev_tool]`
//! emits, so a macro-derived tool has no un-normalized form anywhere: the MCP
//! router, `vibrev_tool_defs()`, the derived CLI and the contract scan are all
//! reading the same bytes. Hand-built [`Tool`]s — session primitives, and the
//! handful of tools too irregular for the macro — get the same treatment from
//! [`normalize_tool`].
//!
//! Normalizing at the exit instead would leave every other consumer looking at
//! the pre-normalized schema, which is how the CLI came to describe parameters
//! in a shape no client was ever offered.

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, RwLock};

use rmcp::model::{JsonObject, Tool};
use schemars::JsonSchema;
use serde_json::{Map, Value};

/// Follow `$ref` hops to the schema they name, giving up rather than looping.
///
/// The hop count is capped rather than cycle-detected: a schema that refers to
/// itself is malformed, and 16 is far past anything schemars emits, so hitting
/// the cap means giving up loudly-as-unknown rather than spinning.
///
/// A `$ref` that does not resolve is returned as-is — reading is not the layer
/// that reports it. [`contract`](crate::contract) is what fails a dangling one.
pub fn deref<'a>(root: &'a Map<String, Value>, schema: &'a Value) -> &'a Value {
    let mut current = schema;
    for _ in 0..16 {
        let Some(r) = current.get("$ref").and_then(Value::as_str) else {
            return current;
        };
        let Some(name) = r
            .strip_prefix("#/$defs/")
            .or_else(|| r.strip_prefix("#/definitions/"))
        else {
            return current;
        };
        let Some(target) = root
            .get("$defs")
            .or_else(|| root.get("definitions"))
            .and_then(Value::as_object)
            .and_then(|defs| defs.get(name))
        else {
            return current;
        };
        current = target;
    }
    current
}

/// `Option<T>` reaches us as `{"type":["string","null"]}` or as an `anyOf` with a
/// null branch, depending on the schemars version and the shape of `T`. Collapse
/// both — and any `$ref` — to the branch that actually describes a value.
pub fn effective<'a>(root: &'a Map<String, Value>, schema: &'a Value) -> &'a Value {
    let schema = deref(root, schema);
    if let Some(branches) = schema
        .get("anyOf")
        .or_else(|| schema.get("oneOf"))
        .and_then(Value::as_array)
    {
        for b in branches {
            let b = deref(root, b);
            if !is_null_branch(b) {
                return b;
            }
        }
    }
    schema
}

/// Only a branch that *says* it is null counts as the null half of an `Option`.
///
/// Testing for "no non-null type" instead would be vacuously true of a branch
/// that declares no `type` at all — and `Option<SomeEnum>` is exactly that:
/// `anyOf: [{$ref: …}, {type: "null"}]` where the `$ref` resolves to a bare
/// `oneOf` of variants. The value branch would be mistaken for the null one,
/// skipped, and the enum would reach the generic tail as an unvalidated string.
pub fn is_null_branch(schema: &Value) -> bool {
    types_of(schema) == ["null"]
}

/// The declared `type`, as a list, for both the string and the array spelling.
pub fn types_of(schema: &Value) -> Vec<&str> {
    match schema.get("type") {
        Some(Value::String(t)) => vec![t.as_str()],
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

/// Whether this node spells optionality as `type: ["T", "null"]`.
///
/// Distinct from [`is_null_branch`]: that one asks "is this *the* null arm",
/// this one asks "does this node carry a null arm inside its own `type`". A
/// bare `{"type":"null"}` is the former and not the latter.
pub fn has_nullable_type_array(schema: &Value) -> bool {
    matches!(schema.get("type"), Some(Value::Array(items))
        if items.len() > 1 && items.iter().any(|item| item.as_str() == Some("null")))
}

/// The index of the null arm inside this node's own `anyOf`/`oneOf`, if it has
/// one. Refs are followed, because `Option<SomeEnum>` puts the *value* arm
/// behind a `$ref` and leaves the null arm inline.
pub fn null_branch_position(root: &Map<String, Value>, schema: &Value) -> Option<usize> {
    let branches = schema
        .get("anyOf")
        .or_else(|| schema.get("oneOf"))
        .and_then(Value::as_array)?;
    // A one-armed `anyOf` of nothing but null is not an `Option<T>` — it is a
    // field that only ever holds null, which is odd but not the shape this rule
    // exists to flatten. Requiring a sibling keeps the rule aimed at optionality.
    if branches.len() < 2 {
        return None;
    }
    branches
        .iter()
        .position(|branch| is_null_branch(deref(root, branch)))
}

/// Rewrite an input schema into the shape this workspace advertises.
///
/// Three changes, all of them removing something schemars emits that downstream
/// tool-calling bridges (OpenAPI-strict validators, function-call translators)
/// handle badly:
///
/// * `$schema` goes. Claude Desktop and others reject a schema that declares its
///   dialect.
/// * `anyOf: [T, {"type": "null"}]` — in either order — collapses to `T`, with
///   the sibling keywords of the `anyOf` node carried onto it. That is schemars'
///   `Option<T>`, and MCP already expresses optionality by leaving the name out
///   of `required`; saying it twice, once structurally, is what makes a bridge
///   generate a nullable argument no caller wants to fill in.
/// * `type: ["X", "null"]` flattens to `type: "X"`, for the same reason.
///
/// Everything else is preserved — `description`, `minimum`, `maximum`, `format`
/// and any vocabulary this crate has never heard of. This is schema cleanup, not
/// a provider workaround: the request types stay portable at the source, and the
/// normalizer only removes shapes that are poor for consumers.
///
/// Idempotent, so applying it to a catalog that was already normalized costs a
/// walk and changes nothing.
pub fn normalize_input(schema: &mut Value) {
    match schema {
        Value::Object(object) => {
            if let Some(collapsed) = collapse_null_branch(object) {
                *object = collapsed;
            }
            object.remove("$schema");
            collapse_nullable_type_array(object);
            for child in object.values_mut() {
                normalize_input(child);
            }
        }
        Value::Array(items) => {
            for item in items {
                normalize_input(item);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// Drop schemars' `$schema` key throughout, and nothing else.
///
/// This is what an *output* schema gets. Deliberately not [`normalize_input`]:
/// that one also collapses the null arm of an `Option`, which is right on the
/// way in — an absent argument is expressed by leaving it out of `required` —
/// and a lie on the way out, where an `Option` field without
/// `skip_serializing_if` really is serialized as `null`. A response saying
/// `{"segment": null}` for an unmapped address is correct, and a schema claiming
/// that key is always an object would fail it.
pub fn strip_dialect(schema: &mut Value) {
    match schema {
        Value::Object(object) => {
            object.remove("$schema");
            for child in object.values_mut() {
                strip_dialect(child);
            }
        }
        Value::Array(items) => {
            for item in items {
                strip_dialect(item);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// Both schemas a tool advertises, normalized in place.
///
/// For a `#[vibrev_tool]` this is already done — [`input_schema_for`] and
/// [`output_schema_for`] ran when the `Tool` was built — and running it again is
/// a no-op. It exists for the tools no macro touched: session primitives, and
/// the ones whose signature the macro cannot dispatch.
pub fn normalize_tool(tool: &mut Tool) {
    rewrite(&mut tool.input_schema, normalize_input);
    if let Some(output_schema) = tool.output_schema.as_mut() {
        rewrite(output_schema, strip_dialect);
    }
}

/// Apply a rewrite to a shared schema, reusing the allocation when this is the
/// only handle to it.
fn rewrite(schema: &mut Arc<JsonObject>, apply: fn(&mut Value)) {
    let mut value = match Arc::get_mut(schema) {
        Some(object) => Value::Object(std::mem::take(object)),
        None => Value::Object((**schema).clone()),
    };
    apply(&mut value);
    let Value::Object(rewritten) = value else {
        // `apply` is one of the two functions above; neither replaces an object
        // node with a scalar.
        unreachable!("normalizing an object schema yields an object schema");
    };
    match Arc::get_mut(schema) {
        Some(object) => *object = rewritten,
        None => *schema = Arc::new(rewritten),
    }
}

/// The normalized input schema for `T`, as `#[vibrev_tool]` advertises it.
///
/// Cached per type, the way rmcp caches the schema this is built from: an engine
/// that rebuilds its catalog on every `tools/list` — which the supervisor faces
/// do, because they graft a session selector onto it — would otherwise re-walk
/// every schema per request.
///
/// The `Err` arm is rmcp's: MCP requires an input schema to be `type: "object"`,
/// and a `Parameters<T>` over a newtype or an enum is not. It reaches the caller
/// rather than panicking here so the message can name the tool.
pub fn input_schema_for<T: JsonSchema + Any>() -> Result<Arc<JsonObject>, String> {
    cached::<T, _>(&INPUT_SCHEMAS, || {
        rmcp::handler::server::common::schema_for_input::<T>().map(|mut schema| {
            rewrite(&mut schema, normalize_input);
            schema
        })
    })
}

/// The output schema for `T` with the dialect marker dropped. See
/// [`strip_dialect`] for why this is the lighter treatment.
pub fn output_schema_for<T: JsonSchema + Any>() -> Arc<JsonObject> {
    cached::<T, _>(&OUTPUT_SCHEMAS, || {
        let mut schema = rmcp::handler::server::common::schema_for_output::<T>();
        rewrite(&mut schema, strip_dialect);
        schema
    })
}

type SchemaCache<V> = LazyLock<RwLock<HashMap<TypeId, V>>>;

static INPUT_SCHEMAS: SchemaCache<Result<Arc<JsonObject>, String>> =
    LazyLock::new(Default::default);
static OUTPUT_SCHEMAS: SchemaCache<Arc<JsonObject>> = LazyLock::new(Default::default);

fn cached<T: Any, V: Clone>(cache: &SchemaCache<V>, build: impl FnOnce() -> V) -> V {
    let key = TypeId::of::<T>();
    if let Some(hit) = cache.read().expect("schema cache").get(&key) {
        return hit.clone();
    }
    let built = build();
    cache
        .write()
        .expect("schema cache")
        .insert(key, built.clone());
    built
}

/// Fold `anyOf`/`oneOf` with exactly one null arm down to what it is really
/// saying, or leave the node alone.
///
/// Two outcomes, because "one value arm" and "several" are different sentences:
/// a lone value arm *is* the field, so it absorbs the node's other keywords and
/// replaces it; several value arms are a genuine union, so only the null arm
/// goes and the union stays.
///
/// The second case is why this reads `oneOf` too, and why it does not insist on
/// a two-armed list: [`null_branch_position`] — which is what
/// [`contract`](crate::contract) reports on — recognises exactly these shapes,
/// and an auditor that flags something the normalizer declines to fix is a test
/// that can never go green.
fn collapse_null_branch(schema: &Map<String, Value>) -> Option<Map<String, Value>> {
    let key = if schema.contains_key("anyOf") {
        "anyOf"
    } else {
        "oneOf"
    };
    let branches = schema.get(key)?.as_array()?;
    // Exactly one null arm. Zero is not optionality; two is a malformed schema,
    // and guessing which one was meant is worse than leaving it to the auditor.
    if branches.iter().filter(|arm| is_null_branch(arm)).count() != 1 {
        return None;
    }

    let kept: Vec<Value> = branches
        .iter()
        .filter(|branch| !is_null_branch(branch))
        .cloned()
        .collect();
    let [only] = kept.as_slice() else {
        // Nothing but null arms says the field only ever holds null — odd, but
        // it is not an `Option<T>` and rewriting it to an empty branch list
        // would turn "only null" into "nothing at all".
        if kept.is_empty() {
            return None;
        }
        let mut replacement = schema.clone();
        replacement.insert(key.to_owned(), Value::Array(kept));
        return Some(replacement);
    };

    let mut replacement = match only {
        Value::Object(branch) => branch.clone(),
        // `true` accepts anything, so the value arm constrains nothing: keep the
        // siblings and drop the branch list.
        Value::Bool(true) => Map::new(),
        // `false` accepts nothing, which would make the whole node "null only" —
        // not the optionality shape. Anything else is not a schema at all.
        Value::Bool(false)
        | Value::Null
        | Value::Number(_)
        | Value::String(_)
        | Value::Array(_) => {
            return None;
        }
    };

    for (name, value) in schema {
        if name != key {
            replacement.insert(name.clone(), value.clone());
        }
    }
    // `Option<T>` with no `#[serde(default = ..)]` arrives carrying
    // `default: null`, which after the collapse would advertise a default the
    // type cannot hold.
    if replacement.get("default").is_some_and(Value::is_null) {
        replacement.remove("default");
    }
    Some(replacement)
}

/// Flatten `type: ["X", "null"]` to `type: "X"`, in place.
///
/// A `type` list of nothing but nulls loses the keyword entirely: `{}` is the
/// honest schema for a field that carries no value, and `type: []` matches
/// nothing at all.
fn collapse_nullable_type_array(schema: &mut Map<String, Value>) {
    let Some(types) = schema.get("type").and_then(Value::as_array) else {
        return;
    };
    if !types.iter().any(|t| t.as_str() == Some("null")) {
        return;
    }
    let mut kept: Vec<Value> = types
        .iter()
        .filter(|t| t.as_str() != Some("null"))
        .cloned()
        .collect();
    match kept.len() {
        0 => {
            schema.remove("type");
        }
        1 => {
            let only = kept.remove(0);
            schema.insert("type".to_owned(), only);
        }
        _ => {
            schema.insert("type".to_owned(), Value::Array(kept));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn root() -> Map<String, Value> {
        json!({"$defs": {"Dialect": {"oneOf": [{"const": "c"}, {"const": "rust"}]}}})
            .as_object()
            .unwrap()
            .clone()
    }

    #[test]
    fn a_null_arm_is_found_through_a_ref_sibling() {
        let root = root();
        let optional_enum = json!({"anyOf": [{"$ref": "#/$defs/Dialect"}, {"type": "null"}]});
        assert_eq!(null_branch_position(&root, &optional_enum), Some(1));
        // …and the value arm is what `effective` hands back, not the null one.
        assert!(effective(&root, &optional_enum).get("oneOf").is_some());
    }

    #[test]
    fn the_two_spellings_of_optional_are_told_apart() {
        assert!(has_nullable_type_array(
            &json!({"type": ["integer", "null"]})
        ));
        assert!(!has_nullable_type_array(&json!({"type": "null"})));
        assert!(is_null_branch(&json!({"type": "null"})));
        assert!(!is_null_branch(&json!({"type": ["integer", "null"]})));
    }

    #[test]
    fn a_lone_null_any_of_is_not_optionality() {
        assert_eq!(
            null_branch_position(&Map::new(), &json!({"anyOf": [{"type": "null"}]})),
            None
        );
    }

    /// A whole schemars `Parameters<T>` product, as `ida-headless-mcp` used to
    /// assert it against its own copy of this function.
    #[test]
    fn an_option_reaches_the_client_as_a_plain_optional_parameter() {
        let mut schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "timeout_secs": {
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "description": "Timeout in seconds",
                    "anyOf": [
                        {"type": "integer", "format": "int64", "minimum": 0, "maximum": 600},
                        {"type": "null"}
                    ],
                    "default": null
                },
                "query": {
                    "type": ["string", "null"],
                    "description": "Optional query"
                }
            }
        });

        normalize_input(&mut schema);

        assert_eq!(
            schema.pointer("/properties/timeout_secs"),
            Some(&json!({
                "type": "integer",
                "format": "int64",
                "minimum": 0,
                "maximum": 600,
                "description": "Timeout in seconds"
            })),
            "the value arm absorbs the node, the null arm and the null default go, \
             and every other keyword survives"
        );
        assert_eq!(
            schema.pointer("/properties/query"),
            Some(&json!({"type": "string", "description": "Optional query"}))
        );
        assert!(!contains_key(&schema, "$schema"));
    }

    /// The normalizer is deliberately conservative about `format`: wire-side
    /// cleanup (no `uint*`) belongs at the Rust type, not here.
    #[test]
    fn formats_are_left_alone() {
        for spelling in [
            json!({"type": "integer", "format": "int64", "minimum": 0}),
            json!({"type": "string", "format": "date-time"}),
            json!({"type": "number", "format": "double"}),
        ] {
            let mut schema = spelling.clone();
            normalize_input(&mut schema);
            assert_eq!(schema, spelling);
        }
    }

    /// A union with a null arm keeps the union. Collapsing to the first branch
    /// would silently narrow what the parameter accepts.
    #[test]
    fn several_value_arms_lose_only_the_null_one() {
        let mut schema = json!({
            "anyOf": [{"type": "integer"}, {"type": "string"}, {"type": "null"}],
            "description": "either"
        });
        normalize_input(&mut schema);
        assert_eq!(
            schema,
            json!({
                "anyOf": [{"type": "integer"}, {"type": "string"}],
                "description": "either"
            })
        );
    }

    /// Whatever the auditor reports, the normalizer removes. A rule that fires
    /// on a shape nothing rewrites is a test that can never go green.
    #[test]
    fn the_auditor_and_the_normalizer_agree_on_what_a_null_arm_is() {
        for shape in [
            json!({"anyOf": [{"type": "integer"}, {"type": "null"}]}),
            json!({"anyOf": [{"type": "null"}, {"type": "integer"}]}),
            json!({"oneOf": [{"$ref": "#/$defs/Dialect"}, {"type": "null"}]}),
            json!({"anyOf": [{"type": "integer"}, {"type": "string"}, {"type": "null"}]}),
        ] {
            let root = root();
            assert!(
                null_branch_position(&root, &shape).is_some(),
                "the auditor should flag {shape}"
            );
            let mut normalized = shape.clone();
            normalize_input(&mut normalized);
            assert!(
                null_branch_position(&root, &normalized).is_none(),
                "the normalizer left {shape} for the auditor to flag again"
            );
        }
    }

    #[test]
    fn normalizing_twice_changes_nothing_the_second_time() {
        let mut once = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {"x": {"anyOf": [{"type": "integer"}, {"type": "null"}]}}
        });
        normalize_input(&mut once);
        let mut twice = once.clone();
        normalize_input(&mut twice);
        assert_eq!(once, twice);
    }

    /// An output schema keeps its null arms: an `Option` field without
    /// `skip_serializing_if` really is serialized as `null`.
    #[test]
    fn the_output_face_loses_the_dialect_and_nothing_else() {
        let mut schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {"segment": {"anyOf": [{"type": "object"}, {"type": "null"}]}}
        });
        strip_dialect(&mut schema);
        assert!(!contains_key(&schema, "$schema"));
        assert_eq!(
            schema.pointer("/properties/segment"),
            Some(&json!({"anyOf": [{"type": "object"}, {"type": "null"}]}))
        );
    }

    /// A branch list with nothing to keep is left alone.
    ///
    /// "Only ever null" is a strange thing for a schema to say, but it says it,
    /// and rewriting it to `anyOf: []` would say something else: that no value
    /// is acceptable at all. The auditor already declines to flag this shape —
    /// see [`null_branch_position`] — so declining to rewrite it keeps the two
    /// agreeing.
    #[test]
    fn a_branch_list_of_nothing_but_null_is_not_rewritten() {
        for shape in [
            json!({"anyOf": [{"type": "null"}]}),
            json!({"anyOf": [{"type": "null"}, {"type": "null"}]}),
        ] {
            let mut normalized = shape.clone();
            normalize_input(&mut normalized);
            assert_eq!(normalized, shape);
        }
    }

    #[test]
    fn a_type_list_of_nothing_but_null_loses_the_keyword() {
        let mut schema = json!({"type": ["null"], "description": "never carries a value"});
        normalize_input(&mut schema);
        assert_eq!(schema, json!({"description": "never carries a value"}));
    }

    /// What `#[vibrev_tool]` emits, end to end.
    #[test]
    fn a_derived_schema_arrives_normalized() {
        #[derive(schemars::JsonSchema)]
        #[allow(dead_code)]
        struct Request {
            name: String,
            limit: Option<u32>,
        }

        let schema = input_schema_for::<Request>().expect("an object-rooted schema");
        let as_value = Value::Object((*schema).clone());
        assert!(!contains_key(&as_value, "$schema"));
        assert_eq!(
            null_branch_position(schema.as_ref(), &as_value["properties"]["limit"]),
            None
        );
        assert_eq!(as_value["properties"]["limit"]["type"], json!("integer"));
        // Optionality is still expressed — by absence from `required`, which is
        // the spelling MCP already has.
        assert_eq!(as_value["required"], json!(["name"]));
    }

    #[test]
    fn the_same_type_is_only_built_once() {
        #[derive(schemars::JsonSchema)]
        #[allow(dead_code)]
        struct Cached {
            x: Option<i64>,
        }

        let first = input_schema_for::<Cached>().expect("schema");
        let second = input_schema_for::<Cached>().expect("schema");
        assert!(Arc::ptr_eq(&first, &second));
    }

    fn contains_key(schema: &Value, key: &str) -> bool {
        match schema {
            Value::Object(object) => {
                object.contains_key(key) || object.values().any(|v| contains_key(v, key))
            }
            Value::Array(items) => items.iter().any(|v| contains_key(v, key)),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
        }
    }
}
