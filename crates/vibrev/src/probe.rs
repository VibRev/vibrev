//! Ask an engine who it is, over MCP.
//!
//! `serverInfo` is the authoritative identity, so this is a real `initialize`
//! handshake and not a `--version` guess: `--version` is whatever the CLI front
//! end feels like printing, while `serverInfo` is what an MCP client — Claude
//! Code, Cursor — will actually see. If the two ever disagree, the one that
//! matters is this one.
//!
//! The probe is strictly bounded. An engine that hangs (IDA wedged in `auto_wait`,
//! a BN license prompt) must degrade `doctor` to one "无法握手" row, never stall it.

use std::process::Stdio;
use std::time::Duration;

use rmcp::ServiceExt;
use rmcp::transport::TokioChildProcess;

use crate::discover::Located;

/// How long to wait for the transport to close after a successful handshake.
/// Shorter than rmcp's own 3 s internal grace period because we already have what
/// we came for and the child is about to be killed regardless.
const SHUTDOWN_GRACE: Duration = Duration::from_millis(800);

#[derive(Debug, Clone)]
pub struct Identity {
    pub name: String,
    pub version: String,
    pub protocol: String,
}

impl Identity {
    /// `rjadx 0.1.0`, the middle column of `doctor`'s table.
    pub fn display(&self) -> String {
        format!("{} {}", self.name, self.version)
    }
}

#[derive(Debug, Clone)]
pub enum Probe {
    Ok(Identity),
    /// Handshake completed but the server sent no `serverInfo`. Allowed by the
    /// spec (`ServerPeerInfo::server_info` is `Option`), useless to us.
    Anonymous {
        protocol: String,
    },
    /// No response within the budget.
    Timeout(Duration),
    /// Spawn failed, the process died, or the handshake was rejected.
    Failed(String),
}

impl Probe {
    pub fn identity(&self) -> Option<&Identity> {
        match self {
            Probe::Ok(i) => Some(i),
            _ => None,
        }
    }

    /// Short reason for the notes column; `None` when everything worked.
    pub fn note(&self) -> Option<String> {
        match self {
            Probe::Ok(_) => None,
            Probe::Anonymous { protocol } => Some(format!(
                "握手成功但未上报 serverInfo（protocol {protocol}）"
            )),
            Probe::Timeout(d) => Some(format!("无法握手：{} 秒内无响应", d.as_secs_f32())),
            Probe::Failed(e) => Some(format!("无法握手：{e}")),
        }
    }
}

/// Spawn the engine in stdio-MCP mode, run `initialize`, read `serverInfo`, kill it.
pub async fn probe(located: &Located, budget: Duration) -> Probe {
    let mut cmd = tokio::process::Command::new(located.path.as_std_path());
    cmd.args(&located.mcp_args);
    // Belt to rmcp's braces: if the handshake times out and the transport is
    // dropped mid-flight, tokio still reaps the child.
    cmd.kill_on_drop(true);

    // rmcp's builder inherits stderr by default. Engines log there, and doctor's
    // whole job is producing a clean table.
    let spawned = TokioChildProcess::builder(cmd)
        .stderr(Stdio::null())
        .spawn();
    let (transport, _stderr) = match spawned {
        Ok(v) => v,
        Err(e) => return Probe::Failed(format!("无法启动：{e}")),
    };

    let service = match tokio::time::timeout(budget, ().serve(transport)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Probe::Failed(e.to_string()),
        Err(_) => {
            // The transport (and with it the child) has just been dropped. Give
            // rmcp's cleanup task a turn on the scheduler before we move on.
            tokio::task::yield_now().await;
            return Probe::Timeout(budget);
        }
    };

    let info = service.peer_info();
    let _ = tokio::time::timeout(SHUTDOWN_GRACE, service.cancel()).await;

    let Some(info) = info else {
        return Probe::Failed("握手完成但没有拿到 peer info".to_owned());
    };
    let protocol = info.protocol_version.to_string();
    match &info.server_info {
        Some(imp) => Probe::Ok(Identity {
            name: imp.name.clone(),
            version: imp.version.clone(),
            protocol,
        }),
        None => Probe::Anonymous { protocol },
    }
}
