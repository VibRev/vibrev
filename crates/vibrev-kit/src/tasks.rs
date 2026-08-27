//! Background work, and the MCP Tasks face over it.
//!
//! An engine puts a call in the background when the answer takes longer than a
//! client will wait: a shared cache loaded from disk, a full analysis pass, a
//! script with a ten-minute ceiling. What the caller gets back is a handle, and
//! from there the conversation is pure protocol — SEP-2663 says how a task is
//! polled, what its terminal payload looks like, who is allowed to cancel it,
//! how long a result stays fetchable. None of that is a fact about the
//! disassembler underneath.
//!
//! So this module is the registry and the adapter onto rmcp's task models, and
//! nothing else. *Which* calls run in the background stays with the engine —
//! that one **is** a fact about the disassembler.
//!
//! # Why a trait and not a decorator
//!
//! [`crate::decorate`] would let this be a wrapper.
//! It is the wrong shape. Answering `tasks/get` needs an **owner**, and who
//! owns a task depends on which transport the request arrived over and whether
//! that transport hands out stable session identity — things the handler knows
//! about itself. A wrapper would have to be handed a copy of them at
//! construction and kept in step forever after. [`TaskHost`] asks the question
//! where the answer already lives, and its three provided methods are the whole
//! `tasks/*` surface.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rmcp::ErrorData;
use rmcp::model::{
    CallToolResponse, CallToolResult, CancelTaskParams, ContentBlock, CreateTaskResult,
    DetailedTask, ErrorCode, GetTaskParams, GetTaskResult, JsonObject, RequestMetaObject,
    TaskPayload, UpdateTaskParams,
};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

/// Protocol TTL advertised from task creation (SEP-2663 `ttlMs`). Terminal
/// entries are pruned this long after their last transition; running tasks are
/// never pruned. A result normally outlives completion by the full TTL, but is
/// reclaimed earlier if it is the oldest terminal entry when the registry hits
/// [`MAX_TASK_REGISTRY_ENTRIES`].
pub const TASK_RETENTION_TTL_MS: u64 = 24 * 60 * 60 * 1000;

/// Hard bound for all retained tasks, including running tasks.
///
/// Terminal entries normally remain available for the full advertised TTL, but
/// admission takes priority over retention: reaching this bound reclaims the
/// least recently updated terminal entries rather than rejecting new work, so
/// a run of completed tasks cannot strand background work for the whole TTL.
/// New work is rejected only when every slot is held by a running task.
pub const MAX_TASK_REGISTRY_ENTRIES: usize = 256;

/// Poll cadence handed to the client with every task handle (SEP-2663
/// `pollIntervalMs`). It is a hint, not a contract, and five seconds suits work
/// measured in minutes — a database load, a full auto-analysis. An engine whose
/// background work settles in seconds should say so by overriding
/// [`TaskHost::task_poll_interval_ms`]; a client that believes this number is
/// a client that waits five seconds to learn something that was ready in one.
pub const DEFAULT_POLL_INTERVAL_MS: u64 = 5_000;

/// Identity allowed to observe and control a task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskOwner {
    /// A stateful legacy HTTP/SSE or stdio MCP session.
    Session(Arc<str>),
    /// Sessionless MCP 2026 requests, which have no stable session identity.
    Runtime,
}

/// Failure to admit a background task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskCreateError {
    /// The same legacy session already has matching work in progress.
    AlreadyRunning(String),
    /// Matching work exists, but its bearer task ID must remain private.
    ExistingTaskIdIsPrivate,
    /// Every slot in the bounded registry is held by a running task, so there
    /// is nothing reclaimable to make room for another.
    CapacityExceeded { max_entries: usize },
}

/// Task status in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Result of attempting to settle a task after its operation returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskSettlement {
    Completed,
    Failed,
    Cancelled,
    Unchanged,
}

/// Atomic decision made at the final successful-result boundary. A pending
/// cancellation remains non-terminal so the caller can clean up resources
/// before publishing `cancelled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskCompletionDecision {
    Completed,
    CancellationPending,
    Unchanged,
}

/// Snapshot of a background task's state (cloneable, no handles).
#[derive(Debug, Clone)]
pub struct TaskState {
    pub id: String,
    pub status: TaskStatus,
    pub message: String,
    pub result: Option<Value>,
    pub created_at: Instant,
    pub updated_at: Instant,
    /// ISO-8601 creation timestamp for the MCP protocol.
    pub created_at_iso: String,
    /// ISO-8601 timestamp for the most recent state/message update.
    pub updated_at_iso: String,
    /// Deduplication key (e.g. the path of the database being produced).
    pub key: Option<String>,
}

/// Internal entry that owns a task's cancellation token.
///
/// Deliberately does not retain the spawned `JoinHandle`: aborting it cannot
/// interrupt an operation blocked in a native call into the analysis engine,
/// since a tokio abort only lands at an await point. Cancellation is
/// cooperative, via the token.
struct TaskEntry {
    owner: TaskOwner,
    state: TaskState,
    cancel_token: Option<CancellationToken>,
    cancel_requested: Option<String>,
}

impl TaskEntry {
    fn new(owner: TaskOwner, state: TaskState) -> Self {
        Self {
            owner,
            state,
            cancel_token: None,
            cancel_requested: None,
        }
    }

    fn set_cancel_token(&mut self, cancel_token: Option<CancellationToken>) {
        if self.cancel_requested.is_some()
            && let Some(cancel_token) = cancel_token.as_ref()
        {
            cancel_token.cancel();
        }
        self.cancel_token = cancel_token;
    }

    fn clear_runtime(&mut self) {
        self.cancel_token = None;
    }

    fn complete(&mut self, result: Value) -> TaskSettlement {
        if self.state.status != TaskStatus::Running {
            return TaskSettlement::Unchanged;
        }
        if let Some(message) = self.cancel_requested.take() {
            self.transition_cancelled(&message);
            return TaskSettlement::Cancelled;
        }

        self.state.status = TaskStatus::Completed;
        self.state.message = "Completed".to_string();
        self.state.result = Some(result);
        refresh_updated(&mut self.state);
        self.clear_runtime();
        TaskSettlement::Completed
    }

    fn fail(&mut self, error: &str) -> TaskSettlement {
        if self.state.status != TaskStatus::Running {
            return TaskSettlement::Unchanged;
        }
        if let Some(message) = self.cancel_requested.take() {
            self.transition_cancelled(&message);
            return TaskSettlement::Cancelled;
        }

        self.state.status = TaskStatus::Failed;
        self.state.message = error.to_string();
        refresh_updated(&mut self.state);
        self.clear_runtime();
        TaskSettlement::Failed
    }

    fn fail_after_cleanup_error(&mut self, error: &str) -> TaskSettlement {
        if self.state.status != TaskStatus::Running {
            return TaskSettlement::Unchanged;
        }

        self.cancel_requested = None;
        self.state.status = TaskStatus::Failed;
        self.state.message = error.to_string();
        refresh_updated(&mut self.state);
        self.clear_runtime();
        TaskSettlement::Failed
    }

    fn request_cancel(&mut self, message: &str) -> bool {
        if self.state.status != TaskStatus::Running || self.cancel_requested.is_some() {
            return false;
        }

        if let Some(cancel_token) = self.cancel_token.as_ref() {
            cancel_token.cancel();
        }
        self.cancel_requested = Some(message.to_string());
        self.state.message = format!("{message}; waiting for the operation to settle");
        refresh_updated(&mut self.state);
        true
    }

    fn transition_cancelled(&mut self, message: &str) {
        self.clear_runtime();
        self.cancel_requested = None;
        self.state.status = TaskStatus::Cancelled;
        self.state.message = message.to_string();
        refresh_updated(&mut self.state);
    }

    fn finish_cancelled(&mut self, message: &str) -> bool {
        if self.state.status != TaskStatus::Running {
            return false;
        }

        self.transition_cancelled(message);
        true
    }

    fn update_message(&mut self, message: &str) {
        if self.state.status == TaskStatus::Running && self.cancel_requested.is_none() {
            self.state.message = message.to_string();
            refresh_updated(&mut self.state);
        }
    }
}

/// Thread-safe registry of background tasks.
#[derive(Clone, Default)]
pub struct TaskRegistry {
    inner: Arc<Mutex<HashMap<String, TaskEntry>>>,
}

impl TaskRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a task with a deduplication key. A legacy session requesting
    /// matching work that it owns receives the existing task ID. All other
    /// matches remain private and block duplicate work. In particular,
    /// sessionless clients share [`TaskOwner::Runtime`], so Runtime matches
    /// never disclose the existing bearer ID.
    /// `prefix` is used in the generated task id (e.g. "open", "analyze").
    pub fn create_keyed(
        &self,
        owner: &TaskOwner,
        prefix: &str,
        key: &str,
        message: &str,
    ) -> Result<String, TaskCreateError> {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        prune_terminal_tasks(&mut entries);

        if let Some(existing) = entries.values().find(|entry| {
            entry.state.status == TaskStatus::Running && entry.state.key.as_deref() == Some(key)
        }) {
            return if matches!(owner, TaskOwner::Session(_)) && &existing.owner == owner {
                Err(TaskCreateError::AlreadyRunning(existing.state.id.clone()))
            } else {
                Err(TaskCreateError::ExistingTaskIdIsPrivate)
            };
        }

        reclaim_capacity_for_admission(&mut entries);
        if entries.len() >= MAX_TASK_REGISTRY_ENTRIES {
            return Err(TaskCreateError::CapacityExceeded {
                max_entries: MAX_TASK_REGISTRY_ENTRIES,
            });
        }

        let id = next_task_id(prefix);
        let (now, created) = now_with_iso();
        let state = TaskState {
            id: id.clone(),
            status: TaskStatus::Running,
            message: message.to_string(),
            result: None,
            created_at: now,
            updated_at: now,
            created_at_iso: created.clone(),
            updated_at_iso: created,
            key: Some(key.to_string()),
        };
        entries.insert(id.clone(), TaskEntry::new(owner.clone(), state));
        Ok(id)
    }

    /// Test fixture: create a terminal task with a precomputed result payload
    /// without going through the create/complete lifecycle.
    #[cfg(test)]
    fn create_completed(
        &self,
        owner: &TaskOwner,
        message: &str,
        result: Value,
    ) -> Result<String, TaskCreateError> {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        prune_terminal_tasks(&mut entries);
        reclaim_capacity_for_admission(&mut entries);
        if entries.len() >= MAX_TASK_REGISTRY_ENTRIES {
            return Err(TaskCreateError::CapacityExceeded {
                max_entries: MAX_TASK_REGISTRY_ENTRIES,
            });
        }
        let id = next_task_id("task");
        let (now, created) = now_with_iso();
        let state = TaskState {
            id: id.clone(),
            status: TaskStatus::Completed,
            message: message.to_string(),
            result: Some(result),
            created_at: now,
            updated_at: now,
            created_at_iso: created.clone(),
            updated_at_iso: created,
            key: None,
        };
        entries.insert(id.clone(), TaskEntry::new(owner.clone(), state));
        Ok(id)
    }

    /// Store the cancellation token for a task.
    ///
    /// Cancels immediately when cancellation was requested before the spawned
    /// operation got far enough to register its token.
    pub fn set_cancel_token(&self, id: &str, cancel_token: CancellationToken) {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = entries.get_mut(id) {
            entry.set_cancel_token(Some(cancel_token));
        }
    }

    /// Get a cloneable snapshot of a task's current state.
    pub fn get(&self, id: &str) -> Option<TaskState> {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        prune_terminal_tasks(&mut entries);
        entries.get(id).map(|e| e.state.clone())
    }

    /// Get a task only when it belongs to the requesting owner. Unknown and
    /// unauthorized IDs deliberately have the same result.
    pub fn get_for_owner(&self, owner: &TaskOwner, id: &str) -> Option<TaskState> {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        prune_terminal_tasks(&mut entries);
        entries
            .get(id)
            .filter(|entry| &entry.owner == owner)
            .map(|entry| entry.state.clone())
    }

    /// Test fixture: list all tasks (snapshots only). Production code resolves
    /// tasks by ID; SEP-2663 dropped `tasks/list`.
    #[cfg(test)]
    fn list_all(&self) -> Vec<TaskState> {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        prune_terminal_tasks(&mut entries);
        entries.values().map(|e| e.state.clone()).collect()
    }

    /// Update the progress message on a running task.
    pub fn update_message(&self, id: &str, message: &str) {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = entries.get_mut(id) {
            entry.update_message(message);
        }
    }

    /// Mark a task as completed with a JSON result.
    pub fn complete(&self, id: &str, result: Value) -> TaskSettlement {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let settlement = match entries.get_mut(id) {
            Some(entry) => entry.complete(result),
            None => TaskSettlement::Unchanged,
        };
        if settlement != TaskSettlement::Unchanged {
            prune_terminal_tasks(&mut entries);
        }
        settlement
    }

    /// Settle a successful operation, publishing cancellation instead when
    /// its lifetime token was cancelled before the registry transition.
    pub fn complete_with_cancel_token(
        &self,
        id: &str,
        result: Value,
        cancel_token: &CancellationToken,
        cancel_message: &str,
    ) -> TaskSettlement {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let settlement = match entries.get_mut(id) {
            Some(entry) if cancel_token.is_cancelled() => {
                if entry.finish_cancelled(cancel_message) {
                    TaskSettlement::Cancelled
                } else {
                    TaskSettlement::Unchanged
                }
            }
            Some(entry) => entry.complete(result),
            None => TaskSettlement::Unchanged,
        };
        if settlement != TaskSettlement::Unchanged {
            prune_terminal_tasks(&mut entries);
        }
        settlement
    }

    /// Complete atomically unless cancellation has already won. Unlike
    /// [`Self::complete_with_cancel_token`], this leaves cancellation pending
    /// so resource cleanup can finish before a terminal state is visible.
    pub fn complete_or_defer_cancellation(
        &self,
        id: &str,
        result: Value,
        cancel_token: &CancellationToken,
    ) -> TaskCompletionDecision {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let decision = match entries.get_mut(id) {
            Some(entry) if entry.state.status != TaskStatus::Running => {
                TaskCompletionDecision::Unchanged
            }
            Some(entry) if cancel_token.is_cancelled() || entry.cancel_requested.is_some() => {
                TaskCompletionDecision::CancellationPending
            }
            Some(entry) => match entry.complete(result) {
                TaskSettlement::Completed => TaskCompletionDecision::Completed,
                TaskSettlement::Failed | TaskSettlement::Cancelled | TaskSettlement::Unchanged => {
                    TaskCompletionDecision::Unchanged
                }
            },
            None => TaskCompletionDecision::Unchanged,
        };
        if decision == TaskCompletionDecision::Completed {
            prune_terminal_tasks(&mut entries);
        }
        decision
    }

    /// Mark a task as failed with an error message.
    pub fn fail(&self, id: &str, error: &str) -> TaskSettlement {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let settlement = match entries.get_mut(id) {
            Some(entry) => entry.fail(error),
            None => TaskSettlement::Unchanged,
        };
        if settlement != TaskSettlement::Unchanged {
            prune_terminal_tasks(&mut entries);
        }
        settlement
    }

    /// Publish a cleanup failure even when cancellation was requested. A task
    /// must not claim clean cancellation when its owned resource could not be
    /// closed or proven replaced.
    pub fn fail_after_cleanup_error(&self, id: &str, error: &str) -> TaskSettlement {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let settlement = match entries.get_mut(id) {
            Some(entry) => entry.fail_after_cleanup_error(error),
            None => TaskSettlement::Unchanged,
        };
        if settlement != TaskSettlement::Unchanged {
            prune_terminal_tasks(&mut entries);
        }
        settlement
    }

    /// Request cancellation only when the task belongs to the owner.
    pub fn cancel_for_owner(&self, owner: &TaskOwner, id: &str) -> bool {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let cancelled = entries
            .get_mut(id)
            .filter(|entry| &entry.owner == owner)
            .is_some_and(|entry| entry.request_cancel("Cancelled by client"));
        if cancelled {
            prune_terminal_tasks(&mut entries);
        }
        cancelled
    }

    pub fn finish_cancelled(&self, id: &str, message: &str) -> bool {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let cancelled = match entries.get_mut(id) {
            Some(entry) => entry.finish_cancelled(message),
            None => false,
        };
        if cancelled {
            prune_terminal_tasks(&mut entries);
        }
        cancelled
    }

    /// Request cancellation for every running task. Returns the number of new
    /// cancellation requests; tasks remain running until their work settles.
    pub fn cancel_all_running(&self, message: &str) -> usize {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let cancelled = entries.values_mut().fold(0, |count, entry| {
            count + usize::from(entry.request_cancel(message))
        });

        if cancelled > 0 {
            prune_terminal_tasks(&mut entries);
        }

        cancelled
    }
}

/// Generate a task ID with a cryptographically random UUIDv4 component.
///
/// The ID is a bearer capability, not just a name: sessionless MCP 2026
/// clients all share [`TaskOwner::Runtime`], so the ID is the only thing
/// separating one client's task (and its result, which can carry a
/// close token) from another's. It must be unguessable — a client that
/// knows its own ID must not be able to derive any other. Full per-task
/// randomness also keeps IDs from different registries (pooled HTTP
/// sessions, worker processes) from colliding, so a stale ID fails lookup
/// instead of resolving to another task.
fn next_task_id(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
}

fn now_with_iso() -> (Instant, String) {
    (Instant::now(), iso_now())
}

fn refresh_updated(state: &mut TaskState) {
    let (updated_at, updated_at_iso) = now_with_iso();
    state.updated_at = updated_at;
    state.updated_at_iso = updated_at_iso;
}

fn prune_terminal_tasks(entries: &mut HashMap<String, TaskEntry>) {
    let retention = std::time::Duration::from_millis(TASK_RETENTION_TTL_MS);
    let now = Instant::now();
    // Measure from `updated_at` (refreshed on the terminal transition), not
    // `created_at`: a task that ran longer than the TTL must stay retrievable
    // after it completes, not vanish in the same call that stored its result.
    entries.retain(|_, entry| {
        entry.state.status == TaskStatus::Running
            || now.saturating_duration_since(entry.state.updated_at) < retention
    });
}

/// Make room for one new task, reclaiming the least recently updated terminal
/// entries when the registry is at capacity.
///
/// The TTL sweep alone lets completed tasks accumulate to the cap well inside
/// the retention window; admission then fails for every new background task
/// even though none are running, and stays failed until the oldest entry ages
/// out. Reclaiming instead means a caller can always make progress while any
/// entry is still reclaimable.
///
/// Deliberately *not* part of [`prune_terminal_tasks`]: that runs on read paths
/// too (`get`, `get_for_owner`), and a read must never discard a result the
/// caller did not ask to drop.
///
/// Running entries are never reclaimed — they hold their slot legitimately, so
/// a registry saturated with in-flight work still reports `CapacityExceeded`.
fn reclaim_capacity_for_admission(entries: &mut HashMap<String, TaskEntry>) {
    if entries.len() < MAX_TASK_REGISTRY_ENTRIES {
        return;
    }

    let mut terminal = Vec::new();
    for (id, entry) in entries.iter() {
        if entry.state.status != TaskStatus::Running {
            terminal.push((entry.state.updated_at, id.clone()));
        }
    }
    terminal.sort_unstable();

    // Free one slot beyond the cap so the caller that triggered this prune can
    // be admitted.
    let excess = entries.len() - MAX_TASK_REGISTRY_ENTRIES + 1;
    for (_, id) in terminal.into_iter().take(excess) {
        entries.remove(&id);
    }
}

/// ISO-8601 timestamp for the current time (UTC).
fn iso_now() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    // Formatted by hand rather than with `chrono`/`time`: the only consumer is
    // a task timestamp, and a date crate is a large dependency for one line of
    // output that no code parses back.
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    let (year, month, day) = epoch_days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn epoch_days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from Howard Hinnant's date library
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

/// Convert a registry snapshot to the base rmcp `Task` model.
pub fn mcp_task(state: &TaskState, poll_interval_ms: u64) -> rmcp::model::Task {
    let status = match state.status {
        TaskStatus::Running => rmcp::model::TaskStatus::Working,
        TaskStatus::Completed => rmcp::model::TaskStatus::Completed,
        TaskStatus::Failed => rmcp::model::TaskStatus::Failed,
        TaskStatus::Cancelled => rmcp::model::TaskStatus::Cancelled,
    };
    rmcp::model::Task::new(
        state.id.clone(),
        status,
        state.created_at_iso.clone(),
        state.updated_at_iso.clone(),
    )
    .with_status_message(state.message.clone())
    .with_ttl_ms(TASK_RETENTION_TTL_MS)
    .with_poll_interval_ms(poll_interval_ms)
}

/// Convert a registry snapshot to the `tasks/get` answer, payload included.
pub fn detailed_task(state: TaskState, poll_interval_ms: u64) -> DetailedTask {
    let base = mcp_task(&state, poll_interval_ms);
    let payload = match state.status {
        TaskStatus::Running => TaskPayload::Working,
        TaskStatus::Completed => TaskPayload::Completed {
            result: value_as_json_object(task_payload_result_value(state.result)),
        },
        TaskStatus::Failed => TaskPayload::Failed {
            error: value_as_json_object(json!({
                "code": ErrorCode::INTERNAL_ERROR.0,
                "message": state.message,
            })),
        },
        TaskStatus::Cancelled => TaskPayload::Cancelled,
    };
    DetailedTask::new(base, payload)
}

fn value_as_json_object(value: Value) -> JsonObject {
    match value {
        Value::Object(object) => object,
        other => {
            let mut object = JsonObject::new();
            object.insert("value".to_string(), other);
            object
        }
    }
}

/// The JSON a task result should carry for an operation that already produced
/// a `CallToolResult` — including a *failed* one.
///
/// A tool that reports failure with `isError: true` did run, so its task
/// completed. Storing the serialized result keeps that distinction on the wire
/// instead of collapsing it into a JSON-RPC error the client cannot tell from
/// a transport fault.
pub fn call_tool_result_to_value(result: &CallToolResult) -> Value {
    serde_json::to_value(result).unwrap_or_else(|_| {
        json!({
            "content": [{
                "type": "text",
                "text": "Failed to serialize CallToolResult"
            }],
            "isError": true
        })
    })
}

fn looks_like_call_tool_result(value: &Value) -> bool {
    serde_json::from_value::<CallToolResult>(value.clone()).is_ok()
}

fn wrap_as_call_tool_result(value: &Value) -> Value {
    let text = serde_json::to_string_pretty(value).unwrap_or_else(|_| format!("{value:?}"));
    call_tool_result_to_value(&CallToolResult::success(vec![ContentBlock::text(text)]))
}

/// SEP-2663 says a completed `tools/call` task carries the result type of the
/// original request. Anything an engine stored that is not already a
/// `CallToolResult` is wrapped in one rather than published as-is.
fn task_payload_result_value(result: Option<Value>) -> Value {
    match result {
        Some(value) if looks_like_call_tool_result(&value) => value,
        Some(value) => wrap_as_call_tool_result(&value),
        None => wrap_as_call_tool_result(&Value::Null),
    }
}

/// Read the task ID back out of a tool result that started background work.
///
/// The universal fallback surface — a `task_status`-style tool every client can
/// call — returns `{"task_id": ...}` as ordinary content, and that same answer
/// is what gets promoted to a protocol task handle for a client that can hold
/// one. Reading the ID back is how one code path serves both.
pub fn task_id_from_call_tool_result(result: &CallToolResult) -> Option<String> {
    result
        .content
        .first()
        .and_then(|content| content.as_text())
        .and_then(|text| serde_json::from_str::<Value>(&text.text).ok())
        .and_then(|value| value.get("task_id")?.as_str().map(str::to_string))
}

fn unknown_task(task_id: &str) -> ErrorData {
    ErrorData::invalid_params("Unknown task_id", Some(json!({ "task_id": task_id })))
}

/// The `tasks/*` half of an engine's `ServerHandler`, expressed as two
/// questions only the engine can answer.
///
/// An engine implements [`task_registry`](Self::task_registry) and
/// [`task_owner`](Self::task_owner) and gets `tasks/get`, `tasks/update` and
/// `tasks/cancel` for free; its `ServerHandler` methods become one line each.
/// None of them is async — the whole surface is a lookup under a mutex — so an
/// engine can call them from an `async fn` without inheriting a future whose
/// `Send`-ness it then has to argue about.
///
/// Owner resolution is the part that stays with the engine, and it is not a
/// formality. Under sessionless MCP 2026 every request builds a fresh handler,
/// so a per-handler identity would make each request the sole owner of nothing;
/// under a legacy session the identity must be the session, so one client
/// cannot read another's result. The engine knows its transport and whether it
/// was started stateless. This module does not.
pub trait TaskHost {
    fn task_registry(&self) -> &TaskRegistry;

    /// Identity that may observe and control tasks created for this request.
    fn task_owner(&self, meta: &RequestMetaObject) -> TaskOwner;

    /// Poll cadence advertised with every handle this engine hands out. See
    /// [`DEFAULT_POLL_INTERVAL_MS`] for when to override it.
    fn task_poll_interval_ms(&self) -> u64 {
        DEFAULT_POLL_INTERVAL_MS
    }

    /// `tasks/get`. Unknown IDs and other owners' IDs answer identically, so
    /// polling cannot be used to discover that a task exists.
    fn serve_get_task(
        &self,
        request: GetTaskParams,
        meta: &RequestMetaObject,
    ) -> Result<GetTaskResult, ErrorData> {
        let owner = self.task_owner(meta);
        let state = self
            .task_registry()
            .get_for_owner(&owner, &request.task_id)
            .ok_or_else(|| unknown_task(&request.task_id))?;
        Ok(GetTaskResult::new(detailed_task(
            state,
            self.task_poll_interval_ms(),
        )))
    }

    /// `tasks/update`.
    ///
    /// SEP-2663 semantics: unknown task ids are an invalid-params error, while
    /// responses delivered to a known task are acknowledged with an empty
    /// result even when unknown or superseded. A task that never enters
    /// `input_required` has no other case — every delivered response falls into
    /// that ignored-not-error bucket.
    fn serve_update_task(
        &self,
        request: UpdateTaskParams,
        meta: &RequestMetaObject,
    ) -> Result<(), ErrorData> {
        let owner = self.task_owner(meta);
        if self
            .task_registry()
            .get_for_owner(&owner, &request.task_id)
            .is_none()
        {
            return Err(unknown_task(&request.task_id));
        }
        Ok(())
    }

    /// `tasks/cancel`. Requesting cancellation twice is acknowledged but only
    /// signals the operation once; the task stays `working` until its work
    /// actually settles, because a cancelled status must mean the resource is
    /// released.
    fn serve_cancel_task(
        &self,
        request: CancelTaskParams,
        meta: &RequestMetaObject,
    ) -> Result<(), ErrorData> {
        let owner = self.task_owner(meta);
        let registry = self.task_registry();
        let Some(state) = registry.get_for_owner(&owner, &request.task_id) else {
            return Err(unknown_task(&request.task_id));
        };
        if state.status == TaskStatus::Running {
            registry.cancel_for_owner(&owner, &request.task_id);
        }
        Ok(())
    }

    /// Promote a tool answer that started background work into a protocol task
    /// handle, when `should_materialize` says the caller can hold one.
    ///
    /// The decision is the engine's, and it has two halves: which tools go to
    /// the background at all, and whether this peer negotiated a protocol
    /// version that can parse `resultType: "task"`. Declaring the tasks
    /// capability is not enough — a peer on an older version cannot read the
    /// answer even if it asked for the extension.
    ///
    /// A result with no `task_id` in it passes through untouched, so a tool
    /// that decided *not* to background this particular call still answers
    /// normally.
    fn materialize_task_response(
        &self,
        should_materialize: bool,
        response: CallToolResponse,
    ) -> Result<CallToolResponse, ErrorData> {
        if !should_materialize {
            return Ok(response);
        }
        let CallToolResponse::Complete(result) = response else {
            return Ok(response);
        };
        let Some(task_id) = task_id_from_call_tool_result(&result) else {
            return Ok(CallToolResponse::Complete(result));
        };
        let state = self.task_registry().get(&task_id).ok_or_else(|| {
            ErrorData::internal_error(format!("Task {task_id} disappeared"), None)
        })?;
        Ok(CreateTaskResult::new(mcp_task(&state, self.task_poll_interval_ms())).into())
    }
}

/// Whether this peer can be handed a task handle at all.
///
/// Two facts, both protocol, and neither sufficient alone. SEP-2663 handles
/// exist from MCP 2026-07-28, so an older peer cannot parse a
/// `resultType: "task"` response *even after* declaring the tasks extension —
/// the capability says what it wants, the version says what it can read. And a
/// modern peer that never declared the extension never agreed to receive one.
///
/// Both arguments are `Option` because rmcp reports them that way: a request
/// that arrived before initialize completed knows neither, and "unknown"
/// answers no.
pub fn peer_can_hold_task_handle(
    protocol_version: Option<rmcp::model::ProtocolVersion>,
    capabilities: Option<rmcp::model::ClientCapabilities>,
) -> bool {
    protocol_version.is_some_and(|version| version >= rmcp::model::ProtocolVersion::V_2026_07_28)
        && capabilities.is_some_and(|capabilities| capabilities.supports_tasks())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    const OWNER: TaskOwner = TaskOwner::Runtime;

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// The smallest thing that can answer `tasks/*`: a registry and one owner.
    struct Host(TaskRegistry);

    impl TaskHost for Host {
        fn task_registry(&self) -> &TaskRegistry {
            &self.0
        }

        fn task_owner(&self, _meta: &RequestMetaObject) -> TaskOwner {
            TaskOwner::Runtime
        }
    }

    fn no_meta() -> RequestMetaObject {
        RequestMetaObject::new()
    }

    /// No engine here ever enters `input_required`, so every `tasks/update`
    /// this module can receive carries an empty response map.
    fn update(task_id: &str) -> UpdateTaskParams {
        UpdateTaskParams::new(task_id.to_string(), Default::default())
    }

    /// Returns `false` when the platform cannot represent an Instant that far
    /// in the past (Windows Instants start at boot), letting callers skip.
    fn age_task_past_retention(registry: &TaskRegistry, id: &str) -> bool {
        let Some(past) =
            Instant::now().checked_sub(Duration::from_millis(TASK_RETENTION_TTL_MS + 1))
        else {
            return false;
        };
        let mut entries = registry.inner.lock().unwrap_or_else(|e| e.into_inner());
        let task = entries.get_mut(id).expect("task should exist before aging");
        task.state.created_at = past;
        task.state.updated_at = past;
        true
    }

    #[test]
    fn create_and_get() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "open", "test-key", "Starting")
            .expect("should succeed");
        assert!(id.starts_with("open-"));
        let state = registry.get(&id).expect("task should exist");
        assert_eq!(state.status, TaskStatus::Running);
        assert_eq!(state.message, "Starting");
        assert!(state.result.is_none());
        assert!(!state.created_at_iso.is_empty());
    }

    #[test]
    fn update_message() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "t", "k1", "Phase 1")
            .expect("should succeed");
        registry.update_message(&id, "Phase 2");
        let state = registry.get(&id).expect("task should exist");
        assert_eq!(state.message, "Phase 2");
    }

    #[test]
    fn complete_task() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "t", "k2", "Working")
            .expect("should succeed");
        let result = json!({"db": "opened"});
        assert_eq!(
            registry.complete(&id, result.clone()),
            TaskSettlement::Completed
        );
        let state = registry.get(&id).expect("task should exist");
        assert_eq!(state.status, TaskStatus::Completed);
        assert_eq!(state.result, Some(result));
    }

    #[test]
    fn fail_task() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "t", "k3", "Working")
            .expect("should succeed");
        assert_eq!(
            registry.fail(&id, "the worker exited with code 4"),
            TaskSettlement::Failed
        );
        let state = registry.get(&id).expect("task should exist");
        assert_eq!(state.status, TaskStatus::Failed);
        assert_eq!(state.message, "the worker exited with code 4");
    }

    #[test]
    fn get_nonexistent() {
        let registry = TaskRegistry::new();
        assert!(registry.get("open-nope").is_none());
    }

    #[test]
    fn runtime_keyed_dedup_keeps_existing_id_private() {
        let registry = TaskRegistry::new();
        let id1 = registry
            .create_keyed(&OWNER, "open", "/path/to/db", "First")
            .expect("first should succeed");
        let dup = registry.create_keyed(&OWNER, "open", "/path/to/db", "Second");
        assert_eq!(dup, Err(TaskCreateError::ExistingTaskIdIsPrivate));

        // After completing, a new task with the same key can be created.
        registry.complete(&id1, json!({}));
        let id2 = registry
            .create_keyed(&OWNER, "open", "/path/to/db", "Third")
            .expect("should succeed after first completed");
        assert_ne!(id1, id2);
    }

    #[test]
    fn task_ownership_isolates_dedup_lookup_and_cancellation() {
        let registry = TaskRegistry::new();
        let owner_a = TaskOwner::Session(Arc::from("session-a"));
        let owner_b = TaskOwner::Session(Arc::from("session-b"));
        let id = registry
            .create_keyed(&owner_a, "open", "/path/to/shared", "Opening")
            .expect("first owner should create the task");

        assert_eq!(
            registry.create_keyed(&owner_a, "open", "/path/to/shared", "Opening again"),
            Err(TaskCreateError::AlreadyRunning(id.clone()))
        );
        assert_eq!(
            registry.create_keyed(&owner_b, "open", "/path/to/shared", "Other owner"),
            Err(TaskCreateError::ExistingTaskIdIsPrivate)
        );
        assert!(registry.get_for_owner(&owner_b, &id).is_none());
        assert!(!registry.cancel_for_owner(&owner_b, &id));
        assert_eq!(
            registry
                .get_for_owner(&owner_a, &id)
                .expect("owner should still see its task")
                .status,
            TaskStatus::Running
        );

        registry.complete(&id, json!({"close_token": "owner-a-secret"}));
        assert!(registry.get_for_owner(&owner_b, &id).is_none());
        assert_eq!(
            registry
                .get_for_owner(&owner_a, &id)
                .and_then(|task| task.result),
            Some(json!({"close_token": "owner-a-secret"}))
        );
    }

    #[test]
    fn cancellation_request_remains_running_until_work_settles() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "t", "k4", "Working")
            .expect("should succeed");
        assert!(registry.cancel_for_owner(&OWNER, &id));
        let state = registry.get(&id).expect("task should exist");
        assert_eq!(state.status, TaskStatus::Running);
        assert!(
            state
                .message
                .contains("waiting for the operation to settle")
        );

        // A repeated request is acknowledged by the protocol handler but does
        // not signal the operation twice.
        assert!(!registry.cancel_for_owner(&OWNER, &id));

        assert_eq!(
            registry.complete(&id, json!({"late_result": true})),
            TaskSettlement::Cancelled
        );
        let state = registry.get(&id).expect("task should remain retained");
        assert_eq!(state.status, TaskStatus::Cancelled);
        assert_eq!(state.message, "Cancelled by client");
        assert!(state.result.is_none());
    }

    #[test]
    fn final_completion_defers_terminal_cancellation_for_cleanup() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "open", "late-cancel", "Working")
            .expect("should create task");
        let cancel_token = CancellationToken::new();

        assert!(registry.cancel_for_owner(&OWNER, &id));
        assert_eq!(
            registry.complete_or_defer_cancellation(
                &id,
                json!({"close_token": "must-not-publish"}),
                &cancel_token,
            ),
            TaskCompletionDecision::CancellationPending
        );
        let pending = registry.get(&id).expect("task should remain visible");
        assert_eq!(pending.status, TaskStatus::Running);
        assert!(pending.result.is_none());

        assert!(registry.finish_cancelled(&id, "database closed"));
        assert_eq!(
            registry
                .get(&id)
                .expect("task should remain retained")
                .status,
            TaskStatus::Cancelled
        );
    }

    #[test]
    fn cancellation_cleanup_failure_is_not_reported_as_clean_cancel() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "open", "cleanup-failed", "Working")
            .expect("should create task");
        assert!(registry.cancel_for_owner(&OWNER, &id));

        assert_eq!(
            registry.fail_after_cleanup_error(&id, "conditional close failed"),
            TaskSettlement::Failed
        );
        let failed = registry.get(&id).expect("task should remain retained");
        assert_eq!(failed.status, TaskStatus::Failed);
        assert_eq!(failed.message, "conditional close failed");
    }

    #[test]
    fn terminal_tasks_ignore_late_complete_or_fail_updates() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "t", "late", "Working")
            .expect("should succeed");

        assert!(registry.cancel_for_owner(&OWNER, &id));
        assert_eq!(
            registry.complete(&id, json!({"ok": true})),
            TaskSettlement::Cancelled
        );
        assert_eq!(
            registry.fail(&id, "late failure"),
            TaskSettlement::Unchanged
        );

        let state = registry.get(&id).expect("task should exist");
        assert_eq!(state.status, TaskStatus::Cancelled);
        assert_eq!(state.message, "Cancelled by client");
        assert!(state.result.is_none());
    }

    #[tokio::test]
    async fn cancel_running_task_signals_cancellation_token() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "t", "k-cancel", "Working")
            .expect("should succeed");
        let cancel_token = CancellationToken::new();
        let observed = cancel_token.clone();
        let wrapper_dropped = Arc::new(AtomicBool::new(false));
        let wrapper_drop_flag = wrapper_dropped.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        // Held to the end of the test: dropping a `JoinHandle` only detaches
        // the task, so the wrapper stays alive either way, but binding it keeps
        // the intent explicit.
        let _handle = tokio::spawn(async move {
            let _drop_flag = DropFlag(wrapper_drop_flag);
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.expect("wrapper should start");
        registry.set_cancel_token(&id, cancel_token);

        assert!(registry.cancel_for_owner(&OWNER, &id));
        assert!(observed.is_cancelled());
        tokio::task::yield_now().await;
        assert!(
            !wrapper_dropped.load(Ordering::SeqCst),
            "requesting cancellation must not abort the wrapper"
        );
        assert_eq!(
            registry.get(&id).expect("task should exist").status,
            TaskStatus::Running
        );
    }

    #[test]
    fn cancelled_lifetime_token_wins_at_operation_settlement() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "t", "lifetime-cancel", "Working")
            .expect("should succeed");
        let cancel_token = CancellationToken::new();
        cancel_token.cancel();

        assert_eq!(
            registry.complete_with_cancel_token(
                &id,
                json!({"late_result": true}),
                &cancel_token,
                "Cancelled after connection closed",
            ),
            TaskSettlement::Cancelled
        );
        let state = registry.get(&id).expect("task should remain retained");
        assert_eq!(state.status, TaskStatus::Cancelled);
        assert_eq!(state.message, "Cancelled after connection closed");
        assert!(state.result.is_none());
    }

    #[tokio::test]
    async fn cancel_all_running_cancels_tokens_and_preserves_terminal_tasks() {
        let registry = TaskRegistry::new();
        let id1 = registry
            .create_keyed(&OWNER, "t", "k-all-1", "Working 1")
            .expect("should succeed");
        let id2 = registry
            .create_keyed(&OWNER, "t", "k-all-2", "Working 2")
            .expect("should succeed");
        let completed = registry
            .create_completed(&OWNER, "Done", json!({"ok": true}))
            .expect("should create completed task");

        let cancel_token1 = CancellationToken::new();
        let cancel_token2 = CancellationToken::new();
        let observed1 = cancel_token1.clone();
        let observed2 = cancel_token2.clone();
        let _handle1 = tokio::spawn(async {
            std::future::pending::<()>().await;
        });
        let _handle2 = tokio::spawn(async {
            std::future::pending::<()>().await;
        });
        registry.set_cancel_token(&id1, cancel_token1);
        registry.set_cancel_token(&id2, cancel_token2);

        assert_eq!(registry.cancel_all_running("Cancelled by shutdown"), 2);
        assert!(observed1.is_cancelled());
        assert!(observed2.is_cancelled());

        let state1 = registry.get(&id1).expect("task should exist");
        let state2 = registry.get(&id2).expect("task should exist");
        let completed_state = registry.get(&completed).expect("task should exist");
        assert_eq!(state1.status, TaskStatus::Running);
        assert_eq!(state2.status, TaskStatus::Running);
        assert_eq!(completed_state.status, TaskStatus::Completed);
        assert_eq!(registry.cancel_all_running("again"), 0);

        assert_eq!(
            registry.complete(&id1, json!({"ok": true})),
            TaskSettlement::Cancelled
        );
        assert_eq!(
            registry.fail(&id2, "the worker settled with an error"),
            TaskSettlement::Cancelled
        );
        assert_eq!(
            registry.get(&id1).expect("task should exist").message,
            "Cancelled by shutdown"
        );
        assert_eq!(
            registry.get(&id2).expect("task should exist").status,
            TaskStatus::Cancelled
        );
    }

    #[test]
    fn list_all_tasks() {
        let registry = TaskRegistry::new();
        let _ = registry.create_keyed(&OWNER, "t", "a", "Task A");
        let _ = registry.create_keyed(&OWNER, "t", "b", "Task B");
        assert_eq!(registry.list_all().len(), 2);
    }

    #[test]
    fn iso_timestamp_format() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "t", "ts", "Timestamp test")
            .expect("should succeed");
        let state = registry.get(&id).expect("task should exist");
        // Should match YYYY-MM-DDTHH:MM:SSZ
        assert!(
            state.created_at_iso.len() == 20,
            "unexpected ISO length: {}",
            state.created_at_iso
        );
        assert!(state.created_at_iso.ends_with('Z'));
    }

    #[test]
    fn create_completed_uses_task_prefix() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_completed(&OWNER, "Done", json!({"ok": true}))
            .expect("should create completed task");
        assert!(id.starts_with("task-"));
        let state = registry.get(&id).expect("task should exist");
        assert_eq!(state.status, TaskStatus::Completed);
    }

    #[test]
    fn task_admission_reclaims_the_oldest_terminal_result_at_capacity() {
        let registry = TaskRegistry::new();
        let mut ids = Vec::with_capacity(MAX_TASK_REGISTRY_ENTRIES);
        for _ in 0..MAX_TASK_REGISTRY_ENTRIES {
            ids.push(
                registry
                    .create_completed(&OWNER, "Done", json!({"ok": true}))
                    .expect("entries within the bound should be admitted"),
            );
        }
        assert_eq!(registry.list_all().len(), MAX_TASK_REGISTRY_ENTRIES);

        // A registry saturated with *terminal* entries must still admit work.
        // Rejecting here would strand every later background call for the whole
        // retention window with nothing running.
        let admitted = registry
            .create_completed(&OWNER, "Admitted", json!({"ok": true}))
            .expect("capacity must be reclaimed from the oldest terminal entry");

        assert_eq!(registry.list_all().len(), MAX_TASK_REGISTRY_ENTRIES);
        assert!(registry.get(&admitted).is_some());
        assert!(
            registry.get(&ids[0]).is_none(),
            "the least recently updated terminal entry should be reclaimed"
        );
        assert!(
            ids[1..].iter().all(|id| registry.get(id).is_some()),
            "reclaiming must take only as many entries as admission needs"
        );
    }

    #[test]
    fn capacity_reclaim_never_evicts_running_tasks() {
        let registry = TaskRegistry::new();
        let mut running = Vec::with_capacity(MAX_TASK_REGISTRY_ENTRIES);
        for index in 0..MAX_TASK_REGISTRY_ENTRIES {
            running.push(
                registry
                    .create_keyed(&OWNER, "t", &format!("k-{index}"), "Working")
                    .expect("entries within the bound should be admitted"),
            );
        }

        assert_eq!(
            registry.create_keyed(&OWNER, "t", "k-overflow", "Working"),
            Err(TaskCreateError::CapacityExceeded {
                max_entries: MAX_TASK_REGISTRY_ENTRIES
            }),
            "in-flight work holds its slot; admission still fails when nothing is reclaimable"
        );
        assert!(
            running.iter().all(|id| registry.get(id).is_some()),
            "running tasks must never be reclaimed"
        );
    }

    #[test]
    fn expired_terminal_task_frees_admission_capacity() {
        let registry = TaskRegistry::new();
        let mut first_id = None;
        for index in 0..MAX_TASK_REGISTRY_ENTRIES {
            let id = registry
                .create_completed(&OWNER, "Done", json!({"index": index}))
                .expect("entries within the bound should be admitted");
            first_id.get_or_insert(id);
        }
        let first_id = first_id.expect("registry bound should be non-zero");
        if !age_task_past_retention(&registry, &first_id) {
            return;
        }

        let replacement = registry
            .create_completed(&OWNER, "Replacement", json!({"ok": true}))
            .expect("expired terminal task should free capacity");
        assert!(registry.get(&first_id).is_none());
        assert!(registry.get(&replacement).is_some());
        assert_eq!(registry.list_all().len(), MAX_TASK_REGISTRY_ENTRIES);
    }

    #[test]
    fn expired_terminal_tasks_are_pruned() {
        let registry = TaskRegistry::new();
        let expired_id = registry
            .create_completed(&OWNER, "Expired", json!({"ok": true}))
            .expect("should create expired fixture");
        let retained_id = registry
            .create_completed(&OWNER, "Retained", json!({"ok": true}))
            .expect("should create retained fixture");

        if !age_task_past_retention(&registry, &expired_id) {
            return;
        }

        assert!(registry.get(&expired_id).is_none());
        assert!(registry.get(&retained_id).is_some());
    }

    #[test]
    fn running_tasks_are_not_pruned_after_retention_ttl() {
        let registry = TaskRegistry::new();
        let running_id = registry
            .create_keyed(&OWNER, "t", "long-running", "Working")
            .expect("should create long-running task");

        if !age_task_past_retention(&registry, &running_id) {
            return;
        }

        assert!(registry.get(&running_id).is_some());
    }

    #[test]
    fn task_completing_after_ttl_remains_retrievable() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "t", "slow", "Working")
            .expect("should create task");

        if !age_task_past_retention(&registry, &id) {
            return;
        }
        registry.complete(&id, json!({"ok": true}));

        assert!(
            registry.get(&id).is_some(),
            "a task older than the TTL must survive its own completion"
        );
    }

    #[test]
    fn task_ids_do_not_collide_across_registries() {
        let first = TaskRegistry::new();
        let second = TaskRegistry::new();
        let a = first
            .create_keyed(&OWNER, "open", "same-key", "Working")
            .expect("should create task");
        let b = second
            .create_keyed(&OWNER, "open", "same-key", "Working")
            .expect("should create task");

        assert_ne!(a, b);
        assert!(second.get(&a).is_none(), "stale IDs must not resolve");
    }

    /// Task IDs are bearer capabilities under the shared sessionless Runtime
    /// owner: each must carry full per-task randomness, never a shared
    /// registry tag plus a guessable counter.
    #[test]
    fn task_ids_are_individually_random_within_one_registry() {
        let registry = TaskRegistry::new();
        let a = registry
            .create_keyed(&OWNER, "open", "key-a", "Working")
            .expect("should create task");
        let b = registry
            .create_keyed(&OWNER, "open", "key-b", "Working")
            .expect("should create task");

        let random_component = |id: &str| {
            id.strip_prefix("open-")
                .expect("task id should start with its prefix")
                .to_string()
        };
        let (a, b) = (random_component(&a), random_component(&b));
        assert_eq!(a.len(), 32, "expected a full 128-bit hex component: {a}");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()), "{a}");
        assert_ne!(a, b, "sibling tasks must not share a derivable component");
    }

    #[test]
    fn task_seed_uses_retention_ttl_and_poll_interval() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "test", "seed", "Working")
            .expect("create task");
        let state = registry.get(&id).expect("task state");
        let value =
            serde_json::to_value(mcp_task(&state, DEFAULT_POLL_INTERVAL_MS)).expect("serialize");

        assert_eq!(value["status"], "working");
        assert_eq!(value["ttlMs"], TASK_RETENTION_TTL_MS);
        assert_eq!(value["pollIntervalMs"], DEFAULT_POLL_INTERVAL_MS);
    }

    /// The poll interval reaches the wire from the host, not from a constant
    /// baked into the adapter. An engine whose work settles in seconds is the
    /// reason it is a method.
    #[test]
    fn host_poll_interval_reaches_the_handle() {
        struct Brisk(TaskRegistry);
        impl TaskHost for Brisk {
            fn task_registry(&self) -> &TaskRegistry {
                &self.0
            }
            fn task_owner(&self, _meta: &RequestMetaObject) -> TaskOwner {
                TaskOwner::Runtime
            }
            fn task_poll_interval_ms(&self) -> u64 {
                250
            }
        }

        let host = Brisk(TaskRegistry::new());
        let id = host
            .0
            .create_keyed(&OWNER, "t", "brisk", "Working")
            .expect("create task");
        let answer = host
            .serve_get_task(GetTaskParams::new(id), &no_meta())
            .expect("owner should read its own task");
        assert_eq!(answer.task.task.poll_interval_ms, Some(250));
    }

    #[test]
    fn task_payload_preserves_valid_call_tool_result() {
        let result = CallToolResult::success(vec![ContentBlock::text("ok")]);
        let as_value = serde_json::to_value(&result).expect("serialize CallToolResult");
        assert_eq!(task_payload_result_value(Some(as_value.clone())), as_value);
    }

    #[test]
    fn task_payload_wraps_content_array_shape_that_is_not_call_tool_result() {
        let input = json!({ "content": [1, 2, 3] });
        let wrapped = task_payload_result_value(Some(input.clone()));
        assert_ne!(wrapped, input);

        let parsed: CallToolResult =
            serde_json::from_value(wrapped).expect("wrapped payload should be CallToolResult");
        assert_eq!(parsed.is_error, Some(false));
        let wrapped_text = parsed
            .content
            .first()
            .and_then(|c| c.as_text())
            .map(|t| t.text.as_str())
            .unwrap_or_default();
        assert!(wrapped_text.contains("\"content\""));
    }

    #[test]
    fn completed_task_inlines_original_tool_result() {
        let registry = TaskRegistry::new();
        let tool_result = CallToolResult::success(vec![ContentBlock::text("done")]);
        let payload = serde_json::to_value(tool_result).expect("serialize tool result");
        let id = registry
            .create_completed(&OWNER, "Completed", payload)
            .expect("create completed task");
        let state = registry.get(&id).expect("task state");
        let value = serde_json::to_value(detailed_task(state, DEFAULT_POLL_INTERVAL_MS))
            .expect("serialize task");

        assert_eq!(value["status"], "completed");
        assert_eq!(value["result"]["content"][0]["text"], "done");
        assert_eq!(value["result"]["isError"], false);
    }

    #[test]
    fn failed_task_inlines_json_rpc_error() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "test", "failed", "Working")
            .expect("create task");
        registry.fail(&id, "the analysis worker exited");
        let state = registry.get(&id).expect("task state");
        let value = serde_json::to_value(detailed_task(state, DEFAULT_POLL_INTERVAL_MS))
            .expect("serialize task");

        assert_eq!(value["status"], "failed");
        assert_eq!(value["error"]["code"], -32603);
        assert_eq!(value["error"]["message"], "the analysis worker exited");
    }

    #[test]
    fn background_tool_result_materializes_a_task_handle() {
        let host = Host(TaskRegistry::new());
        let task_id = host
            .0
            .create_keyed(&OWNER, "open", "/tmp/cache", "Opening")
            .expect("create task");
        let result = CallToolResult::success(vec![ContentBlock::text(
            serde_json::to_string(&json!({"task_id": task_id})).expect("serialize result"),
        )]);
        let response = host
            .materialize_task_response(true, CallToolResponse::Complete(result))
            .expect("materialize task");

        let CallToolResponse::Task(created) = response else {
            panic!("a task-capable call must return a task handle");
        };
        assert_eq!(created.task.task_id, task_id);
        assert_eq!(created.task.status, rmcp::model::TaskStatus::Working);
        assert_eq!(
            created.task.poll_interval_ms,
            Some(DEFAULT_POLL_INTERVAL_MS)
        );
        assert_eq!(created.task.ttl_ms, Some(TASK_RETENTION_TTL_MS));
    }

    /// A tool that decided against backgrounding this call answers normally.
    /// The alternative — an internal error because no `task_id` was in the
    /// payload — would turn a per-call decision into a per-tool one.
    #[test]
    fn a_result_without_a_task_id_passes_through() {
        let host = Host(TaskRegistry::new());
        let result = CallToolResult::success(vec![ContentBlock::text("{\"done\":true}")]);
        let response = host
            .materialize_task_response(true, CallToolResponse::Complete(result))
            .expect("pass through");
        assert!(matches!(response, CallToolResponse::Complete(_)));
    }

    #[test]
    fn update_task_acknowledges_known_tasks_and_rejects_unknown() {
        let host = Host(TaskRegistry::new());
        let id = host
            .0
            .create_keyed(&OWNER, "open", "update-task", "Working")
            .expect("create task");

        // SEP-2663: responses delivered to a known task are ignored with an
        // empty result, never an error — including after a raced transition
        // to a terminal state.
        assert!(host.serve_update_task(update(&id), &no_meta()).is_ok());
        host.0.complete(&id, json!({"ok": true}));
        assert!(host.serve_update_task(update(&id), &no_meta()).is_ok());

        let err = host
            .serve_update_task(update("missing-1"), &no_meta())
            .expect_err("unknown task must error");
        assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
    }

    /// Another owner's ID is answered exactly like an ID that never existed,
    /// on every one of the three verbs. Anything else turns `tasks/get` into
    /// an oracle for whether a task exists.
    #[test]
    fn another_owners_task_is_indistinguishable_from_a_missing_one() {
        struct Owned(TaskRegistry, TaskOwner);
        impl TaskHost for Owned {
            fn task_registry(&self) -> &TaskRegistry {
                &self.0
            }
            fn task_owner(&self, _meta: &RequestMetaObject) -> TaskOwner {
                self.1.clone()
            }
        }

        let registry = TaskRegistry::new();
        let mine = TaskOwner::Session(Arc::from("session-a"));
        let id = registry
            .create_keyed(&mine, "open", "/path/to/shared", "Opening")
            .expect("create task");
        let stranger = Owned(registry, TaskOwner::Session(Arc::from("session-b")));

        let missing = stranger
            .serve_get_task(GetTaskParams::new("open-missing".to_string()), &no_meta())
            .expect_err("unknown id must error");
        let theirs = stranger
            .serve_get_task(GetTaskParams::new(id.clone()), &no_meta())
            .expect_err("another owner's id must error");
        assert_eq!(theirs.code, missing.code);
        assert_eq!(theirs.message, missing.message);

        assert_eq!(
            stranger
                .serve_cancel_task(CancelTaskParams::new(id.clone()), &no_meta())
                .expect_err("another owner must not cancel")
                .code,
            ErrorCode::INVALID_PARAMS
        );
        assert_eq!(
            stranger
                .serve_update_task(update(&id), &no_meta())
                .expect_err("another owner must not update")
                .code,
            ErrorCode::INVALID_PARAMS
        );
        assert_eq!(
            stranger
                .task_registry()
                .get(&id)
                .expect("the task itself is untouched")
                .status,
            TaskStatus::Running,
        );
    }

    #[test]
    fn cancel_leaves_the_task_running_until_its_work_settles() {
        let host = Host(TaskRegistry::new());
        let id = host
            .0
            .create_keyed(&OWNER, "open", "cancel-verb", "Working")
            .expect("create task");

        host.serve_cancel_task(CancelTaskParams::new(id.clone()), &no_meta())
            .expect("owner may cancel");
        let state = host.0.get(&id).expect("task should exist");
        assert_eq!(state.status, TaskStatus::Running);

        // Acknowledged again rather than rejected: a client that retries a
        // cancel it already sent has not made a protocol error.
        host.serve_cancel_task(CancelTaskParams::new(id.clone()), &no_meta())
            .expect("a repeated cancel is acknowledged");

        host.0.complete(&id, json!({"late": true}));
        let settled = host.0.get(&id).expect("task should remain retained");
        assert_eq!(settled.status, TaskStatus::Cancelled);

        // Terminal now, and still not an error to ask again.
        host.serve_cancel_task(CancelTaskParams::new(id), &no_meta())
            .expect("cancelling a settled task is acknowledged");
    }

    /// Version and capability are an AND, and the version half is the one an
    /// engine forgets: a client can declare the tasks extension while speaking
    /// a protocol that cannot parse the answer.
    #[test]
    fn a_task_handle_needs_both_the_capability_and_the_version() {
        use rmcp::model::{ClientCapabilities, ProtocolVersion};

        let asked = ClientCapabilities::builder().enable_tasks().build();
        let silent = ClientCapabilities::default();

        assert!(peer_can_hold_task_handle(
            Some(ProtocolVersion::V_2026_07_28),
            Some(asked.clone())
        ));
        assert!(!peer_can_hold_task_handle(
            Some(ProtocolVersion::V_2025_11_25),
            Some(asked.clone())
        ));
        assert!(!peer_can_hold_task_handle(
            Some(ProtocolVersion::V_2026_07_28),
            Some(silent)
        ));
        assert!(!peer_can_hold_task_handle(None, Some(asked)));
    }
}
