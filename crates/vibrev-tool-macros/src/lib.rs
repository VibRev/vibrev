//! `#[vibrev_tool]` / `#[vibrev_tool_router]` — one definition, two surfaces.
//!
//! `#[vibrev_tool_router]` rewrites every `#[vibrev_tool]` in the impl block into
//! `#[rmcp::tool]`, then delegates to `#[rmcp::tool_router]`. On top of what rmcp
//! generates it emits three more items:
//!
//! * `vibrev_tool_defs()` — the `Tool` structs paired with their CLI hints
//! * `vibrev_cli(bin)`    — an [`EngineCli`](vibrev_kit::cli::EngineCli) builder for
//!   the `clap::Command` tree, built from those same `Tool`s. Optional
//!   `group_about(binary = "...", annotation = "...")` on this attribute is
//!   threaded through so `tool --help` is not empty for group Commands.
//! * `vibrev_call(name, args)` — dispatch by tool name into the same function bodies
//!
//! Because all of this expands in one compilation unit, the MCP surface and the CLI
//! cannot drift: changing a tool signature updates both, and omitting the required
//! metadata is a compile error rather than a runtime surprise.

use darling::{FromMeta, ast::NestedMeta};
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{ImplItem, ItemImpl};

/// Tool annotations, in shorthand. Translated to rmcp's `*_hint` names.
#[derive(FromMeta, Default, Debug)]
#[darling(default)]
struct Annotations {
    read_only: Option<bool>,
    destructive: Option<bool>,
    idempotent: Option<bool>,
    open_world: Option<bool>,
}

/// CLI hints. These never cross a process boundary — the CLI is built in-process
/// from the same binary — so they stay out of the tool's `_meta`.
#[derive(FromMeta, Default, Debug)]
#[darling(default)]
struct CliAttr {
    /// Comma-separated parameter names to render as positional arguments.
    positional: Option<String>,
    /// Comma-separated parameter names that accept `184` / `0xb8` / `0b1011`.
    int_args: Option<String>,
    /// Exclude this tool from the CLI entirely.
    none: bool,
    /// This tool does not read the engine's session, so the CLI must not demand
    /// one. For the few tools that answer out of a catalog or out of arithmetic
    /// — `tool_help`, `tool_catalog`, `int_convert` — rather than out of the
    /// open database.
    no_session: bool,
}

#[derive(FromMeta, Default, Debug)]
#[darling(default)]
struct ToolAttr {
    group: Option<String>,
    verb: Option<String>,
    name: Option<String>,
    title: Option<String>,
    /// Tool description. Omit it and rmcp takes the doc comment, which is the
    /// idiomatic form; engines whose descriptions are already string literals
    /// (and whose exact bytes are a published contract) pass them through here.
    description: Option<String>,
    /// Output payload type, as a path: `output = "responses::FunctionListResult"`.
    ///
    /// Needed by any tool that does not return [`Rendered<T>`](vibrev_kit::Rendered) —
    /// rmcp derives `outputSchema` only from `Json<T>`, so a tool returning a
    /// hand-built `CallToolResult` has no other way to say what it publishes.
    output: Option<String>,
    ext: Option<String>,
    annotations: Option<Annotations>,
    cli: Option<CliAttr>,
}

/// Marks a tool. Only meaningful inside an `#[vibrev_tool_router]` impl block,
/// which consumes it; if it ever expands on its own the router attribute is missing.
#[proc_macro_attribute]
pub fn vibrev_tool(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item: TokenStream2 = item.into();
    quote! {
        ::core::compile_error!(
            "#[vibrev_tool] requires the enclosing impl block to carry #[vibrev_tool_router]"
        );
        #item
    }
    .into()
}

#[proc_macro_attribute]
pub fn vibrev_tool_router(attr: TokenStream, item: TokenStream) -> TokenStream {
    match expand(attr.into(), item.into()) {
        Ok(ts) => ts.into(),
        Err(e) => e.into_compile_error().into(),
    }
}

fn csv(s: &Option<String>) -> Vec<String> {
    s.as_deref()
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Pull `T` out of `Rendered<T>`, looking through a `Result<_, _>` wrapper.
///
/// rmcp derives `outputSchema` only from `Json<T>`, so a tool returning
/// [`Rendered<T>`](vibrev_kit::Rendered) — which keeps the readable text in `content` —
/// would silently publish no output schema. Detecting it here lets the macro emit the
/// schema explicitly, so choosing readable output costs nothing.
fn rendered_inner(ret: &syn::ReturnType) -> Option<syn::Type> {
    fn inner(ty: &syn::Type, want: &str) -> Option<syn::Type> {
        let syn::Type::Path(p) = ty else { return None };
        let seg = p.path.segments.last()?;
        if seg.ident != want {
            return None;
        }
        let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
            return None;
        };
        match args.args.first()? {
            syn::GenericArgument::Type(t) => Some(t.clone()),
            _ => None,
        }
    }

    let syn::ReturnType::Type(_, ty) = ret else {
        return None;
    };
    inner(ty, "Rendered").or_else(|| inner(&inner(ty, "Result")?, "Rendered"))
}

/// Find the `Parameters<T>` argument, and refuse anything else.
///
/// The CLI reaches a tool with a name and a JSON object and nothing more, so a
/// handler that also wants a `RequestContext`, MRTR `RequestState` or
/// `InputResponses` has inputs the CLI cannot supply. That is a real boundary,
/// not an oversight — and naming it at compile time is the whole point of doing
/// this in a macro. The alternative is an arity mismatch deep inside the
/// expansion, which says nothing about why.
///
/// Returns the `T` of the `Parameters<T>`, which is also the type the input
/// schema is generated from — the kit normalizes it at that point, so a derived
/// tool has no un-normalized schema anywhere (see `vibrev_kit::schema`).
fn parameters_arg(sig: &syn::Signature) -> syn::Result<Option<syn::Type>> {
    let mut found: Option<syn::Type> = None;
    for arg in sig.inputs.iter() {
        let syn::FnArg::Typed(t) = arg else { continue };
        if let Some(payload) = parameters_payload(&t.ty) {
            let payload = payload?;
            if found.is_some() {
                return Err(syn::Error::new_spanned(
                    arg,
                    "a tool takes at most one `Parameters<..>` argument",
                ));
            }
            found = Some(payload);
            continue;
        }
        return Err(syn::Error::new_spanned(
            arg,
            format!(
                "`{}` takes an argument the CLI front end cannot supply — only \
                 `&self` and one `Parameters<T>` are dispatchable. Extractors such as \
                 `RequestContext`, `RequestState` or `InputResponses` exist on the MCP \
                 request and have no command-line equivalent; leave this tool on plain \
                 `#[rmcp::tool]` instead of `#[vibrev_tool]`.",
                sig.ident
            ),
        ));
    }
    Ok(found)
}

/// The `T` in a `Parameters<T>`, or `None` for an argument of any other type.
///
/// The inner `Result` is for a `Parameters` whose payload cannot be read: the
/// schema is derived from that type, so an elided or non-type argument is an
/// error to report rather than an argument to pass over.
fn parameters_payload(ty: &syn::Type) -> Option<syn::Result<syn::Type>> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    let segment = path.path.segments.last()?;
    if segment.ident != "Parameters" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &segment.arguments else {
        return Some(Err(syn::Error::new_spanned(
            ty,
            "`Parameters` needs its type argument spelled out: the input schema is derived from it",
        )));
    };
    let Some(syn::GenericArgument::Type(payload)) = args.args.first() else {
        return Some(Err(syn::Error::new_spanned(
            ty,
            "`Parameters<..>` must name a type to derive the input schema from",
        )));
    };
    Some(Ok(payload.clone()))
}

fn expand(attr: TokenStream2, item: TokenStream2) -> syn::Result<TokenStream2> {
    let RouterNames {
        defs_name,
        cli_name,
        call_name,
    } = RouterNames::parse(&attr)?;
    let group_about = parse_group_about(&attr)?;
    let mut item_impl: ItemImpl = syn::parse2(item)?;

    let mut defs: Vec<TokenStream2> = Vec::new();
    let mut arms: Vec<TokenStream2> = Vec::new();

    for it in item_impl.items.iter_mut() {
        let ImplItem::Fn(f) = it else { continue };
        let Some(idx) = f.attrs.iter().position(|a| {
            a.path()
                .segments
                .last()
                .is_some_and(|s| s.ident == "vibrev_tool")
        }) else {
            continue;
        };
        let raw = f.attrs.remove(idx);
        let parsed: ToolAttr = match &raw.meta {
            syn::Meta::Path(_) => ToolAttr::default(),
            other => {
                let list = other.require_list()?;
                let nested = NestedMeta::parse_meta_list(list.tokens.clone())?;
                ToolAttr::from_list(&nested)
                    .map_err(|e| syn::Error::new_spanned(&raw, e.to_string()))?
            }
        };

        let fn_ident = f.sig.ident.clone();
        let name = parsed.name.clone().unwrap_or_else(|| {
            match (parsed.group.as_deref(), parsed.verb.as_deref()) {
                (Some(g), Some(v)) => format!("{g}.{v}"),
                (None, Some(v)) => v.to_owned(),
                _ => fn_ident.to_string(),
            }
        });

        // The highest-ROI metadata, enforced at compile time so it cannot be
        // silently skipped.
        let Some(title) = parsed.title.clone() else {
            return Err(syn::Error::new_spanned(
                &f.sig,
                format!("tool `{name}` is missing `title = \"...\"`"),
            ));
        };
        let Some(ann) = parsed.annotations else {
            return Err(syn::Error::new_spanned(
                &f.sig,
                format!("tool `{name}` is missing `annotations(read_only = ...)`"),
            ));
        };
        let Some(read_only) = ann.read_only else {
            return Err(syn::Error::new_spanned(
                &f.sig,
                format!("tool `{name}` must state `annotations(read_only = true|false)`"),
            ));
        };

        let mut hints = vec![quote!(read_only_hint = #read_only)];
        if let Some(v) = ann.destructive {
            hints.push(quote!(destructive_hint = #v));
        }
        if let Some(v) = ann.idempotent {
            hints.push(quote!(idempotent_hint = #v));
        }
        if let Some(v) = ann.open_world {
            hints.push(quote!(open_world_hint = #v));
        }

        let params = parameters_arg(&f.sig)?;

        let mut rmcp_args: Vec<TokenStream2> = vec![
            quote!(name = #name),
            quote!(title = #title),
            quote!(annotations(#(#hints),*)),
        ];
        if let Some(desc) = &parsed.description {
            rmcp_args.push(quote!(description = #desc));
        }
        // Both schemas come from the kit rather than from rmcp's defaults, so
        // the shape this engine advertises is decided once, where the `Tool` is
        // built — see `vibrev_kit::schema`. rmcp would otherwise hand the router
        // schemars' raw output while every other consumer (the derived CLI, the
        // contract scan, a supervisor grafting a session selector on) read a
        // catalog someone remembered to normalize afterwards.
        if let Some(payload) = &params {
            rmcp_args.push(quote! {
                input_schema = ::vibrev_kit::schema::input_schema_for::<#payload>()
                    .unwrap_or_else(|e| ::std::panic!("tool `{}`: {}", #name, e))
            });
        }
        // An explicit `output` wins: a tool that hand-builds its `CallToolResult`
        // knows its payload type, and nothing in the signature says it.
        let output = match parsed.output.as_deref() {
            Some(path) => Some(syn::parse_str::<syn::Type>(path).map_err(|e| {
                syn::Error::new_spanned(
                    &f.sig,
                    format!("tool `{name}`: `output = \"{path}\"` is not a type path: {e}"),
                )
            })?),
            None => rendered_inner(&f.sig.output),
        };
        if let Some(payload) = output {
            rmcp_args.push(quote! {
                output_schema = ::vibrev_kit::schema::output_schema_for::<#payload>()
            });
        }

        // Put it back where `#[vibrev_tool]` was rather than at the end: engines
        // stack `#[instrument]` and friends on their tools, and attribute macros
        // expand outside-in, so the position is observable.
        f.attrs.insert(
            idx,
            syn::parse_quote! {
                #[::rmcp::tool(#(#rmcp_args),*)]
            },
        );

        let attr_fn = format_ident!("{fn_ident}_tool_attr");
        let positional = csv(&parsed.cli.as_ref().and_then(|c| c.positional.clone()));
        let int_args = csv(&parsed.cli.as_ref().and_then(|c| c.int_args.clone()));
        let enabled = !parsed.cli.as_ref().map(|c| c.none).unwrap_or(false);
        let needs_session = !parsed.cli.as_ref().map(|c| c.no_session).unwrap_or(false);
        let ext = match parsed.ext.as_deref() {
            Some(e) => quote!(::core::option::Option::Some(#e)),
            None => quote!(::core::option::Option::None),
        };

        defs.push(quote! {
            ::vibrev_kit::ToolDef {
                tool: Self::#attr_fn(),
                cli: ::vibrev_kit::CliHints {
                    positional: &[#(#positional),*],
                    int_args: &[#(#int_args),*],
                    enabled: #enabled,
                    needs_session: #needs_session,
                },
                ext: #ext,
            }
        });

        // Dispatch into the *same* function body the MCP router calls, and then
        // through the *same* trait it converts with. The macro deliberately does
        // not look at the return type: `IntoCallToolResult` is implemented for
        // `Rendered<T>`, `Json<T>`, `CallToolResult`, `CallToolResponse` and for
        // `Result<T, E>` over any of them, so every shape rmcp's router accepts
        // reaches the CLI too — and reaches it by exactly the route the MCP
        // surface takes, rather than by a reimplementation that has to be kept
        // in step. Unwrapping a known newtype here instead is what made the CLI
        // path a second opinion, and it is what made engines returning
        // `Result<CallToolResult, _>` — that is, all 78 IDA tools — unbuildable.
        let invoke = if params.is_some() {
            quote! {
                let __p = ::serde_json::from_value(args).map_err(|e| {
                    ::rmcp::ErrorData::invalid_params(::std::string::ToString::to_string(&e), None)
                })?;
                Self::#fn_ident(self, ::rmcp::handler::server::wrapper::Parameters(__p)).await
            }
        } else {
            quote! {
                let _ = args;
                Self::#fn_ident(self).await
            }
        };
        arms.push(quote! {
            #name => {
                let __out = { #invoke };
                let __response =
                    ::rmcp::handler::server::tool::IntoCallToolResult::into_call_tool_result(__out)?;
                ::vibrev_kit::ToolOutcome::from_response(__response)
            }
        });
    }

    if defs.is_empty() {
        return Err(syn::Error::new_spanned(
            &item_impl,
            "#[vibrev_tool_router] found no #[vibrev_tool] functions in this impl block",
        ));
    }

    item_impl.items.push(syn::parse_quote! {
        /// Every tool in this engine, paired with its CLI hints.
        pub fn #defs_name() -> ::std::vec::Vec<::vibrev_kit::ToolDef> {
            ::std::vec![#(#defs),*]
        }
    });
    let group_about_chain = if group_about.is_empty() {
        TokenStream2::new()
    } else {
        let pairs = group_about
            .iter()
            .map(|(group, text)| quote! { (#group, #text) });
        quote! {
            .with_group_about(&[#(#pairs),*])
        }
    };
    item_impl.items.push(syn::parse_quote! {
        /// The CLI command tree, built from the same `Tool` structs the MCP surface serves.
        ///
        /// Returns a builder, not a finished `clap::Command`: the engine gets to name
        /// its own management commands first, because the collision check has to run
        /// against what this engine actually registers rather than against a list the
        /// kit guessed. Finish with `.with_management(&[..]).command()`, or
        /// just `.command()` to keep `vibrev_kit::cli::RESERVED` as the fallback.
        pub fn #cli_name(bin: &'static str) -> ::vibrev_kit::cli::EngineCli {
            ::vibrev_kit::cli::EngineCli::new(bin, Self::#defs_name())
                #group_about_chain
        }
    });
    item_impl.items.push(syn::parse_quote! {
        /// Invoke a tool by name. Used by the CLI front end; the MCP router reaches
        /// the identical function bodies through `ToolRouter`.
        ///
        /// The `Err` arm is a *call* failure (bad arguments, unknown tool, a
        /// transport-level `ErrorData` from the handler). A tool that ran and
        /// reported failure comes back as `Ok` with
        /// [`is_error`](vibrev_kit::ToolOutcome::is_error) set, because that is
        /// how MCP models it and squashing the two would make the CLI disagree
        /// with the MCP surface about what happened.
        pub async fn #call_name(
            &self,
            name: &str,
            args: ::serde_json::Value,
        ) -> ::std::result::Result<::vibrev_kit::ToolOutcome, ::rmcp::ErrorData> {
            match name {
                #(#arms)*
                other => ::std::result::Result::Err(::rmcp::ErrorData::invalid_params(
                    ::std::format!("unknown tool: {other}"),
                    None,
                )),
            }
        }
    });
    let try_call_name = format_ident!("try_{call_name}");
    item_impl.items.push(syn::parse_quote! {
        pub async fn #try_call_name(
            &self,
            name: &str,
            args: ::serde_json::Value,
        ) -> ::std::option::Option<
            ::std::result::Result<::vibrev_kit::ToolOutcome, ::rmcp::ErrorData>,
        > {
            match self.#call_name(name, args).await {
                ::std::result::Result::Err(error)
                    if error.message.starts_with("unknown tool:") =>
                {
                    ::std::option::Option::None
                }
                other => ::std::option::Option::Some(other),
            }
        }
    });

    // Forward only what rmcp understands. `defs` / `cli` / `call` name our
    // derived methods; rmcp's darling parser rejects unknown fields.
    let rmcp_attr = rmcp_tool_router_attr(&attr)?;
    Ok(if rmcp_attr.is_empty() {
        quote! {
            #[::rmcp::tool_router]
            #item_impl
        }
    } else {
        quote! {
            #[::rmcp::tool_router(#rmcp_attr)]
            #item_impl
        }
    })
}

fn rmcp_tool_router_attr(attr: &TokenStream2) -> syn::Result<TokenStream2> {
    if attr.is_empty() {
        return Ok(TokenStream2::new());
    }
    let metas = NestedMeta::parse_meta_list(attr.clone())?;
    let kept: Vec<&NestedMeta> = metas
        .iter()
        .filter(|meta| match meta {
            NestedMeta::Meta(syn::Meta::NameValue(nv)) => nv.path.get_ident().is_none_or(|id| {
                let name = id.to_string();
                name != "defs" && name != "cli" && name != "call"
            }),
            NestedMeta::Meta(syn::Meta::List(list)) => {
                list.path.get_ident().is_none_or(|id| id != "group_about")
            }
            NestedMeta::Meta(syn::Meta::Path(path)) => {
                path.get_ident().is_none_or(|id| id != "group_about")
            }
            _ => true,
        })
        .collect();
    Ok(quote! { #(#kept),* })
}

/// Optional names for the three methods this macro pushes into the impl.
///
/// Defaults stay `vibrev_tool_defs` / `vibrev_cli` / `vibrev_call` so a single
/// router keeps compiling. A second `#[vibrev_tool_router]` on the same type
/// must pick different names (and usually a different `router =`) or the
/// methods collide.
struct RouterNames {
    defs_name: syn::Ident,
    cli_name: syn::Ident,
    call_name: syn::Ident,
}

impl RouterNames {
    fn parse(attr: &TokenStream2) -> syn::Result<Self> {
        let mut defs_name = format_ident!("vibrev_tool_defs");
        let mut cli_name = format_ident!("vibrev_cli");
        let mut call_name = format_ident!("vibrev_call");
        if attr.is_empty() {
            return Ok(Self {
                defs_name,
                cli_name,
                call_name,
            });
        }
        let metas = NestedMeta::parse_meta_list(attr.clone())?;
        for meta in metas {
            let NestedMeta::Meta(syn::Meta::NameValue(nv)) = &meta else {
                continue;
            };
            let Some(ident) = nv.path.get_ident() else {
                continue;
            };
            let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(lit),
                ..
            }) = &nv.value
            else {
                continue;
            };
            match ident.to_string().as_str() {
                "defs" => defs_name = format_ident!("{}", lit.value()),
                "cli" => cli_name = format_ident!("{}", lit.value()),
                "call" => call_name = format_ident!("{}", lit.value()),
                // `router` / `vis` belong to rmcp; leave them on `attr`.
                _ => {}
            }
        }
        Ok(Self {
            defs_name,
            cli_name,
            call_name,
        })
    }
}

/// `group_about(binary = "...", annotation = "...")` — about text for clap
/// group Commands, which otherwise inherit nothing from the leaf tools.
fn parse_group_about(attr: &TokenStream2) -> syn::Result<Vec<(String, String)>> {
    if attr.is_empty() {
        return Ok(Vec::new());
    }
    let metas = NestedMeta::parse_meta_list(attr.clone())?;
    let mut out = Vec::new();
    for meta in metas {
        match &meta {
            NestedMeta::Meta(syn::Meta::NameValue(nv))
                if nv.path.get_ident().is_some_and(|id| id == "group_about") =>
            {
                return Err(syn::Error::new_spanned(
                    nv,
                    "group_about takes nested assignments: \
                     group_about(binary = \"...\", annotation = \"...\")",
                ));
            }
            NestedMeta::Meta(syn::Meta::Path(path))
                if path.get_ident().is_some_and(|id| id == "group_about") =>
            {
                return Err(syn::Error::new_spanned(
                    path,
                    "group_about takes nested assignments: \
                     group_about(binary = \"...\")",
                ));
            }
            NestedMeta::Meta(syn::Meta::List(list))
                if list.path.get_ident().is_some_and(|id| id == "group_about") =>
            {
                parse_group_about_entries(list, &mut out)?;
            }
            _ => {}
        }
    }
    Ok(out)
}

fn parse_group_about_entries(
    list: &syn::MetaList,
    out: &mut Vec<(String, String)>,
) -> syn::Result<()> {
    let nested = NestedMeta::parse_meta_list(list.tokens.clone())?;
    for item in nested {
        let NestedMeta::Meta(syn::Meta::NameValue(nv)) = &item else {
            return Err(syn::Error::new_spanned(
                &item,
                "group_about entries must be `name = \"...\"`",
            ));
        };
        let Some(ident) = nv.path.get_ident() else {
            return Err(syn::Error::new_spanned(
                &nv.path,
                "group_about keys must be identifiers (use `r#type` for the `type` group)",
            ));
        };
        // `r#type` Display includes the `r#` prefix; clap groups are named `type`.
        let displayed = ident.to_string();
        let key = displayed
            .strip_prefix("r#")
            .unwrap_or(&displayed)
            .to_owned();
        let syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(lit),
            ..
        }) = &nv.value
        else {
            return Err(syn::Error::new_spanned(
                &nv.value,
                "group_about values must be string literals",
            ));
        };
        if out.iter().any(|(k, _)| k == &key) {
            return Err(syn::Error::new_spanned(
                &nv.path,
                format!("group_about: `{key}` specified twice"),
            ));
        }
        out.push((key, lit.value()));
    }
    Ok(())
}
