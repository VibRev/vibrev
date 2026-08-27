//! One place that knows the whole `ServerHandler` surface.
//!
//! A decorator written as a bare `impl rmcp::ServerHandler` implements the
//! methods whoever wrote it had in mind. rmcp's defaults answer the rest — an
//! empty resource list, an empty prompt list, `-32601` for a read. Nothing
//! warns: the decorator compiles, its own tests pass, and a capability the
//! inner server does implement is gone from the wire.
//!
//! That is not hypothetical. [`crate::output::Capped`] forwarded six of
//! twenty-eight methods, and wrapping `ida-headless-mcp`'s supervisor in it
//! left the server still advertising `resources` in its capabilities while
//! `resources/list` returned `[]` and `resources/read` returned
//! `-32601 method not found`. The engine's `ida://` handling was untouched and
//! unreachable, and the tests that would have caught it did not exist because
//! the surface they would have had to enumerate lived in someone else's crate.
//!
//! So a decorator here does not implement `ServerHandler`. It implements
//! [`Decorator`], where every method already passes through to the inner
//! server, and overrides the one or two it exists to change.
//! [`decorated_handler!`] writes the `ServerHandler` impl from that. Forgetting
//! a method stops being possible, because there is nothing to forget: the
//! default *is* the forward.
//!
//! The list below is therefore the only copy of rmcp's server surface in this
//! workspace. An rmcp upgrade that adds a method is a compile error here and
//! nowhere else.

// Logging (`set_level`) and `resources/subscribe` are SEP-2577-deprecated, but
// they are still on the trait this mirrors, and a legacy peer still calls them.
// Not forwarding them would be this module's own bug in miniature.
#![expect(deprecated)]

use std::borrow::Cow;
use std::future::Future;

use rmcp::ErrorData;
use rmcp::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CancelTaskParams, CancelledNotificationParam,
    CompleteRequestParams, CompleteResult, CustomNotification, CustomRequest, CustomResult,
    DiscoverResult, GetPromptRequestParams, GetPromptResponse, GetTaskParams, GetTaskResult,
    InitializeRequestParams, InitializeResult, ListPromptsResult, ListResourceTemplatesResult,
    ListResourcesResult, ListToolsResult, PaginatedRequestParams, ProgressNotificationParam,
    ProtocolVersion, ReadResourceRequestParams, ReadResourceResponse, ServerInfo,
    SetLevelRequestParams, SubscribeRequestParams, SubscriptionFilter, Tool,
    UnsubscribeRequestParams, UpdateTaskParams,
};
use rmcp::service::{
    MaybeSendFuture, NotificationContext, RequestContext, RoleServer, SubscriptionContext,
};

/// A server handler that changes part of another one and passes the rest
/// through.
///
/// Implement this, override what the decorator is for, and generate the
/// `ServerHandler` impl with [`decorated_handler!`]:
///
/// ```ignore
/// impl<S: rmcp::ServerHandler + Send + Sync> Decorator for Quiet<S> {
///     type Inner = S;
///     fn inner(&self) -> &S { &self.inner }
///
///     fn list_tools(&self, params, ctx) -> impl Future<..> + MaybeSendFuture + '_ {
///         async move { /* … */ }
///     }
/// }
/// vibrev_kit::decorated_handler!(impl<S: rmcp::ServerHandler + Send + Sync> for Quiet<S>);
/// ```
///
/// Every method mirrors [`rmcp::ServerHandler`]'s signature exactly, so an
/// override reads the same as it would have there.
pub trait Decorator: Send + Sync + 'static {
    /// The handler being decorated.
    type Inner: rmcp::ServerHandler;

    fn inner(&self) -> &Self::Inner;

    fn ping(
        &self,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<(), ErrorData>> + MaybeSendFuture + '_ {
        self.inner().ping(context)
    }

    /// Forwards, then republishes `self.get_info()` over the answer.
    ///
    /// The subtle half of decorating. rmcp's default `initialize` builds its
    /// reply out of `self.get_info()`, so a decorator that adds a capability
    /// there — the whole point of, say, a tasks decorator — and forwards
    /// `initialize` verbatim would show that capability in `get_info` and never
    /// on the wire. `protocol_version` is the one field kept from the inner
    /// answer: it is the outcome of a negotiation against the inner server's
    /// supported list, and not ours to restate.
    fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<InitializeResult, ErrorData>> + MaybeSendFuture + '_ {
        async move {
            let negotiated = self.inner().initialize(request, context).await?;
            let mut info = self.get_info();
            info.protocol_version = negotiated.protocol_version;
            Ok(info)
        }
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        self.inner().supported_protocol_versions()
    }

    /// Forwards, then republishes the three fields this decorator can own.
    ///
    /// Same reason as [`initialize`](Self::initialize): rmcp's default builds
    /// the answer from `self.get_info()` and `self.supported_protocol_versions()`,
    /// so a decorator that changes either and forwards `discover` verbatim would
    /// publish the wrong one. `ttl_ms` and `cache_scope` are cache policy the
    /// inner server chose and stay as it set them.
    fn discover(
        &self,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<DiscoverResult, ErrorData>> + MaybeSendFuture + '_ {
        async move {
            let mut result = self.inner().discover(context).await?;
            let info = self.get_info();
            result.capabilities = info.capabilities;
            result.instructions = info.instructions;
            result.supported_versions = self.supported_protocol_versions().into_owned();
            Ok(result)
        }
    }

    fn complete(
        &self,
        request: CompleteRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CompleteResult, ErrorData>> + MaybeSendFuture + '_ {
        self.inner().complete(request, context)
    }

    fn set_level(
        &self,
        request: SetLevelRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<(), ErrorData>> + MaybeSendFuture + '_ {
        self.inner().set_level(request, context)
    }

    fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<GetPromptResponse, ErrorData>> + MaybeSendFuture + '_ {
        self.inner().get_prompt(request, context)
    }

    fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListPromptsResult, ErrorData>> + MaybeSendFuture + '_ {
        self.inner().list_prompts(request, context)
    }

    fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourcesResult, ErrorData>> + MaybeSendFuture + '_ {
        self.inner().list_resources(request, context)
    }

    fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourceTemplatesResult, ErrorData>> + MaybeSendFuture + '_
    {
        self.inner().list_resource_templates(request, context)
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ReadResourceResponse, ErrorData>> + MaybeSendFuture + '_ {
        self.inner().read_resource(request, context)
    }

    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        self.inner().accepted_subscription_filter(requested)
    }

    fn listen(
        &self,
        context: SubscriptionContext,
    ) -> impl Future<Output = Result<(), ErrorData>> + MaybeSendFuture + '_ {
        self.inner().listen(context)
    }

    fn subscribe(
        &self,
        request: SubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<(), ErrorData>> + MaybeSendFuture + '_ {
        self.inner().subscribe(request, context)
    }

    fn unsubscribe(
        &self,
        request: UnsubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<(), ErrorData>> + MaybeSendFuture + '_ {
        self.inner().unsubscribe(request, context)
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CallToolResponse, ErrorData>> + MaybeSendFuture + '_ {
        self.inner().call_tool(request, context)
    }

    fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, ErrorData>> + MaybeSendFuture + '_ {
        self.inner().list_tools(request, context)
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.inner().get_tool(name)
    }

    fn on_custom_request(
        &self,
        request: CustomRequest,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CustomResult, ErrorData>> + MaybeSendFuture + '_ {
        self.inner().on_custom_request(request, context)
    }

    fn on_cancelled(
        &self,
        notification: CancelledNotificationParam,
        context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = ()> + MaybeSendFuture + '_ {
        self.inner().on_cancelled(notification, context)
    }

    fn on_progress(
        &self,
        notification: ProgressNotificationParam,
        context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = ()> + MaybeSendFuture + '_ {
        self.inner().on_progress(notification, context)
    }

    fn on_initialized(
        &self,
        context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = ()> + MaybeSendFuture + '_ {
        self.inner().on_initialized(context)
    }

    fn on_roots_list_changed(
        &self,
        context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = ()> + MaybeSendFuture + '_ {
        self.inner().on_roots_list_changed(context)
    }

    fn on_custom_notification(
        &self,
        notification: CustomNotification,
        context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = ()> + MaybeSendFuture + '_ {
        self.inner().on_custom_notification(notification, context)
    }

    fn get_info(&self) -> ServerInfo {
        self.inner().get_info()
    }

    fn get_task(
        &self,
        request: GetTaskParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<GetTaskResult, ErrorData>> + MaybeSendFuture + '_ {
        self.inner().get_task(request, context)
    }

    fn update_task(
        &self,
        request: UpdateTaskParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<(), ErrorData>> + MaybeSendFuture + '_ {
        self.inner().update_task(request, context)
    }

    fn cancel_task(
        &self,
        request: CancelTaskParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<(), ErrorData>> + MaybeSendFuture + '_ {
        self.inner().cancel_task(request, context)
    }
}

/// Write the [`rmcp::ServerHandler`] impl for a [`Decorator`].
///
/// ```ignore
/// vibrev_kit::decorated_handler!(Capped<S>, generic S: rmcp::ServerHandler + Send + Sync);
/// vibrev_kit::decorated_handler!(MyConcreteServer);
/// ```
///
/// The generic parameters come last and after the word `generic` because an
/// `impl<…>` prefix inside a `macro_rules!` pattern is ambiguous: `tt` matches
/// the closing `>`, so the parser cannot tell where the list ends.
///
/// Every method delegates to the same method on [`Decorator`], so the impl is
/// complete by construction. The caller's crate needs `rmcp` as a dependency;
/// every consumer of this macro has one by definition.
#[macro_export]
macro_rules! decorated_handler {
    ($target:ty) => {
        $crate::decorated_handler!($target, generic);
    };
    ($target:ty, generic $($generics:tt)*) => {
        #[allow(deprecated)]
        impl<$($generics)*> ::rmcp::ServerHandler for $target {
            fn ping(
                &self,
                context: ::rmcp::service::RequestContext<::rmcp::service::RoleServer>,
            ) -> impl ::core::future::Future<Output = ::core::result::Result<(), ::rmcp::ErrorData>>
                   + ::rmcp::service::MaybeSendFuture + '_ {
                $crate::decorate::Decorator::ping(self, context)
            }

            fn initialize(
                &self,
                request: ::rmcp::model::InitializeRequestParams,
                context: ::rmcp::service::RequestContext<::rmcp::service::RoleServer>,
            ) -> impl ::core::future::Future<
                    Output = ::core::result::Result<::rmcp::model::InitializeResult, ::rmcp::ErrorData>,
                > + ::rmcp::service::MaybeSendFuture + '_ {
                $crate::decorate::Decorator::initialize(self, request, context)
            }

            fn supported_protocol_versions(
                &self,
            ) -> ::std::borrow::Cow<'static, [::rmcp::model::ProtocolVersion]> {
                $crate::decorate::Decorator::supported_protocol_versions(self)
            }

            fn discover(
                &self,
                context: ::rmcp::service::RequestContext<::rmcp::service::RoleServer>,
            ) -> impl ::core::future::Future<
                    Output = ::core::result::Result<::rmcp::model::DiscoverResult, ::rmcp::ErrorData>,
                > + ::rmcp::service::MaybeSendFuture + '_ {
                $crate::decorate::Decorator::discover(self, context)
            }

            fn complete(
                &self,
                request: ::rmcp::model::CompleteRequestParams,
                context: ::rmcp::service::RequestContext<::rmcp::service::RoleServer>,
            ) -> impl ::core::future::Future<
                    Output = ::core::result::Result<::rmcp::model::CompleteResult, ::rmcp::ErrorData>,
                > + ::rmcp::service::MaybeSendFuture + '_ {
                $crate::decorate::Decorator::complete(self, request, context)
            }

            fn set_level(
                &self,
                request: ::rmcp::model::SetLevelRequestParams,
                context: ::rmcp::service::RequestContext<::rmcp::service::RoleServer>,
            ) -> impl ::core::future::Future<Output = ::core::result::Result<(), ::rmcp::ErrorData>>
                   + ::rmcp::service::MaybeSendFuture + '_ {
                $crate::decorate::Decorator::set_level(self, request, context)
            }

            fn get_prompt(
                &self,
                request: ::rmcp::model::GetPromptRequestParams,
                context: ::rmcp::service::RequestContext<::rmcp::service::RoleServer>,
            ) -> impl ::core::future::Future<
                    Output = ::core::result::Result<::rmcp::model::GetPromptResponse, ::rmcp::ErrorData>,
                > + ::rmcp::service::MaybeSendFuture + '_ {
                $crate::decorate::Decorator::get_prompt(self, request, context)
            }

            fn list_prompts(
                &self,
                request: ::core::option::Option<::rmcp::model::PaginatedRequestParams>,
                context: ::rmcp::service::RequestContext<::rmcp::service::RoleServer>,
            ) -> impl ::core::future::Future<
                    Output = ::core::result::Result<::rmcp::model::ListPromptsResult, ::rmcp::ErrorData>,
                > + ::rmcp::service::MaybeSendFuture + '_ {
                $crate::decorate::Decorator::list_prompts(self, request, context)
            }

            fn list_resources(
                &self,
                request: ::core::option::Option<::rmcp::model::PaginatedRequestParams>,
                context: ::rmcp::service::RequestContext<::rmcp::service::RoleServer>,
            ) -> impl ::core::future::Future<
                    Output = ::core::result::Result<::rmcp::model::ListResourcesResult, ::rmcp::ErrorData>,
                > + ::rmcp::service::MaybeSendFuture + '_ {
                $crate::decorate::Decorator::list_resources(self, request, context)
            }

            fn list_resource_templates(
                &self,
                request: ::core::option::Option<::rmcp::model::PaginatedRequestParams>,
                context: ::rmcp::service::RequestContext<::rmcp::service::RoleServer>,
            ) -> impl ::core::future::Future<
                    Output = ::core::result::Result<
                        ::rmcp::model::ListResourceTemplatesResult,
                        ::rmcp::ErrorData,
                    >,
                > + ::rmcp::service::MaybeSendFuture + '_ {
                $crate::decorate::Decorator::list_resource_templates(self, request, context)
            }

            fn read_resource(
                &self,
                request: ::rmcp::model::ReadResourceRequestParams,
                context: ::rmcp::service::RequestContext<::rmcp::service::RoleServer>,
            ) -> impl ::core::future::Future<
                    Output = ::core::result::Result<::rmcp::model::ReadResourceResponse, ::rmcp::ErrorData>,
                > + ::rmcp::service::MaybeSendFuture + '_ {
                $crate::decorate::Decorator::read_resource(self, request, context)
            }

            fn accepted_subscription_filter(
                &self,
                requested: &::rmcp::model::SubscriptionFilter,
            ) -> ::core::option::Option<::rmcp::model::SubscriptionFilter> {
                $crate::decorate::Decorator::accepted_subscription_filter(self, requested)
            }

            fn listen(
                &self,
                context: ::rmcp::service::SubscriptionContext,
            ) -> impl ::core::future::Future<Output = ::core::result::Result<(), ::rmcp::ErrorData>>
                   + ::rmcp::service::MaybeSendFuture + '_ {
                $crate::decorate::Decorator::listen(self, context)
            }

            fn subscribe(
                &self,
                request: ::rmcp::model::SubscribeRequestParams,
                context: ::rmcp::service::RequestContext<::rmcp::service::RoleServer>,
            ) -> impl ::core::future::Future<Output = ::core::result::Result<(), ::rmcp::ErrorData>>
                   + ::rmcp::service::MaybeSendFuture + '_ {
                $crate::decorate::Decorator::subscribe(self, request, context)
            }

            fn unsubscribe(
                &self,
                request: ::rmcp::model::UnsubscribeRequestParams,
                context: ::rmcp::service::RequestContext<::rmcp::service::RoleServer>,
            ) -> impl ::core::future::Future<Output = ::core::result::Result<(), ::rmcp::ErrorData>>
                   + ::rmcp::service::MaybeSendFuture + '_ {
                $crate::decorate::Decorator::unsubscribe(self, request, context)
            }

            fn call_tool(
                &self,
                request: ::rmcp::model::CallToolRequestParams,
                context: ::rmcp::service::RequestContext<::rmcp::service::RoleServer>,
            ) -> impl ::core::future::Future<
                    Output = ::core::result::Result<::rmcp::model::CallToolResponse, ::rmcp::ErrorData>,
                > + ::rmcp::service::MaybeSendFuture + '_ {
                $crate::decorate::Decorator::call_tool(self, request, context)
            }

            fn list_tools(
                &self,
                request: ::core::option::Option<::rmcp::model::PaginatedRequestParams>,
                context: ::rmcp::service::RequestContext<::rmcp::service::RoleServer>,
            ) -> impl ::core::future::Future<
                    Output = ::core::result::Result<::rmcp::model::ListToolsResult, ::rmcp::ErrorData>,
                > + ::rmcp::service::MaybeSendFuture + '_ {
                $crate::decorate::Decorator::list_tools(self, request, context)
            }

            fn get_tool(&self, name: &str) -> ::core::option::Option<::rmcp::model::Tool> {
                $crate::decorate::Decorator::get_tool(self, name)
            }

            fn on_custom_request(
                &self,
                request: ::rmcp::model::CustomRequest,
                context: ::rmcp::service::RequestContext<::rmcp::service::RoleServer>,
            ) -> impl ::core::future::Future<
                    Output = ::core::result::Result<::rmcp::model::CustomResult, ::rmcp::ErrorData>,
                > + ::rmcp::service::MaybeSendFuture + '_ {
                $crate::decorate::Decorator::on_custom_request(self, request, context)
            }

            fn on_cancelled(
                &self,
                notification: ::rmcp::model::CancelledNotificationParam,
                context: ::rmcp::service::NotificationContext<::rmcp::service::RoleServer>,
            ) -> impl ::core::future::Future<Output = ()> + ::rmcp::service::MaybeSendFuture + '_ {
                $crate::decorate::Decorator::on_cancelled(self, notification, context)
            }

            fn on_progress(
                &self,
                notification: ::rmcp::model::ProgressNotificationParam,
                context: ::rmcp::service::NotificationContext<::rmcp::service::RoleServer>,
            ) -> impl ::core::future::Future<Output = ()> + ::rmcp::service::MaybeSendFuture + '_ {
                $crate::decorate::Decorator::on_progress(self, notification, context)
            }

            fn on_initialized(
                &self,
                context: ::rmcp::service::NotificationContext<::rmcp::service::RoleServer>,
            ) -> impl ::core::future::Future<Output = ()> + ::rmcp::service::MaybeSendFuture + '_ {
                $crate::decorate::Decorator::on_initialized(self, context)
            }

            fn on_roots_list_changed(
                &self,
                context: ::rmcp::service::NotificationContext<::rmcp::service::RoleServer>,
            ) -> impl ::core::future::Future<Output = ()> + ::rmcp::service::MaybeSendFuture + '_ {
                $crate::decorate::Decorator::on_roots_list_changed(self, context)
            }

            fn on_custom_notification(
                &self,
                notification: ::rmcp::model::CustomNotification,
                context: ::rmcp::service::NotificationContext<::rmcp::service::RoleServer>,
            ) -> impl ::core::future::Future<Output = ()> + ::rmcp::service::MaybeSendFuture + '_ {
                $crate::decorate::Decorator::on_custom_notification(self, notification, context)
            }

            fn get_info(&self) -> ::rmcp::model::ServerInfo {
                $crate::decorate::Decorator::get_info(self)
            }

            fn get_task(
                &self,
                request: ::rmcp::model::GetTaskParams,
                context: ::rmcp::service::RequestContext<::rmcp::service::RoleServer>,
            ) -> impl ::core::future::Future<
                    Output = ::core::result::Result<::rmcp::model::GetTaskResult, ::rmcp::ErrorData>,
                > + ::rmcp::service::MaybeSendFuture + '_ {
                $crate::decorate::Decorator::get_task(self, request, context)
            }

            fn update_task(
                &self,
                request: ::rmcp::model::UpdateTaskParams,
                context: ::rmcp::service::RequestContext<::rmcp::service::RoleServer>,
            ) -> impl ::core::future::Future<Output = ::core::result::Result<(), ::rmcp::ErrorData>>
                   + ::rmcp::service::MaybeSendFuture + '_ {
                $crate::decorate::Decorator::update_task(self, request, context)
            }

            fn cancel_task(
                &self,
                request: ::rmcp::model::CancelTaskParams,
                context: ::rmcp::service::RequestContext<::rmcp::service::RoleServer>,
            ) -> impl ::core::future::Future<Output = ::core::result::Result<(), ::rmcp::ErrorData>>
                   + ::rmcp::service::MaybeSendFuture + '_ {
                $crate::decorate::Decorator::cancel_task(self, request, context)
            }
        }
    };
}
