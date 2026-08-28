//! `vibrev token rotate` — partial-failure-safe token rotation.
//!
//! The listener accepts **every** line of `~/.vibrev/token`, not just the first.
//! Rotation exploits that: the new token is written first, previous tokens stay
//! on later lines, and client configs are rewritten afterwards. A rewrite that
//! fails halfway therefore cannot take a client offline — the old credential is
//! still accepted. Dropping the old lines is a separate, explicit `--expire-old`
//! step, and it will not run without `--yes`.
//!
//! That first sentence is a property of `vibrev_kit::token`, which both ends of
//! the contract share and where a test holds it. This module's own scope is the
//! part that is genuinely the installer's: which client config files hold a
//! token of ours, and what happens to them.
//!
//! Project-scope files are scanned so we can *report* them, but they never
//! receive a token.

use anyhow::{Result, anyhow};
use camino::{Utf8Path, Utf8PathBuf};
use serde_json::{Value, json};
use vibrev_kit::token::{self as shared, TokenError};

use crate::atomic;
use crate::client::{self, Client, Env, Scope};
use crate::config::Paths;
use crate::mcpfile;

/// CLI flags. Domain behaviour is [`ExpireOld`]; these exist so `main` can map
/// clap's `--expire-old` / `--yes` without leaking clap into this module.
pub struct RotateOpts {
    pub expire_old: bool,
    pub yes: bool,
}

/// Whether this invocation should drop previously accepted tokens after rewrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpireOld {
    Keep,
    /// List configs that would then 401, then drop the old lines iff `confirmed`.
    Drop {
        confirmed: bool,
    },
}

impl RotateOpts {
    fn expire(&self) -> ExpireOld {
        if self.expire_old {
            ExpireOld::Drop {
                confirmed: self.yes,
            }
        } else {
            ExpireOld::Keep
        }
    }
}

#[derive(Debug)]
pub struct Hit {
    pub file: Utf8PathBuf,
    pub client: &'static str,
    pub scope: Scope,
    pub servers: Vec<String>,
}

#[derive(Debug)]
pub struct Fail {
    pub file: Utf8PathBuf,
    pub client: &'static str,
    pub scope: Scope,
    pub reason: String,
}

#[derive(Debug)]
pub struct Report {
    pub token_file: Utf8PathBuf,
    pub current: String,
    pub previous_count: usize,
    /// The token file was readable by other users on this host *before* this
    /// run rewrote it at 0600. The rotation fixes the mode, which is why this
    /// is not a warning about the file: it is a warning about the token the
    /// rotation is moving away from.
    pub previous_exposed: bool,
    pub rewritten: Vec<Hit>,
    pub failed: Vec<Fail>,
    pub skipped_project: Vec<Hit>,
    pub would_break: Vec<Hit>,
    pub expired_old: bool,
    pub expire_refused: bool,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.failed.is_empty() && !self.expire_refused
    }

    pub fn to_json(&self) -> Value {
        json!({
            "ok": self.ok(),
            "tokenFile": self.token_file.as_str(),
            "current": self.current,
            "previousCount": self.previous_count,
            "previousExposed": self.previous_exposed,
            "rewritten": self.rewritten.iter().map(Hit::to_json).collect::<Vec<_>>(),
            "failed": self.failed.iter().map(|f| json!({
                "file": f.file.as_str(),
                "client": f.client,
                "scope": f.scope.as_str(),
                "error": f.reason,
            })).collect::<Vec<_>>(),
            "skippedProject": self.skipped_project.iter().map(Hit::to_json).collect::<Vec<_>>(),
            "wouldBreak": self.would_break.iter().map(Hit::to_json).collect::<Vec<_>>(),
            "expiredOld": self.expired_old,
            "expireRefused": self.expire_refused,
        })
    }

    pub fn render(&self, paths: &Paths) -> String {
        let mut out = String::from("已轮换 HTTP bearer token\n");
        out.push_str(&format!(
            "  文件    {}\n",
            paths.abbreviate(&self.token_file)
        ));
        out.push_str(&format!("  当前    {}\n", self.current));
        if self.previous_exposed {
            out.push_str(
                "  注意    轮换前的 token 文件其他用户可读；旧 token 应视为已泄漏（文件权限已改回 0600）\n",
            );
        }
        if self.previous_count > 0 && !self.expired_old {
            out.push_str(&format!(
                "  旧 token 仍被接受（{} 个），回写完成前不会失效\n",
                self.previous_count
            ));
        }

        if self.rewritten.is_empty() && self.failed.is_empty() && self.skipped_project.is_empty() {
            out.push_str("  没有需要回写的 HTTP 客户端配置。\n");
        }

        if !self.rewritten.is_empty() {
            out.push_str("\n已回写:\n");
            for h in &self.rewritten {
                out.push_str(&format!(
                    "  {}  {}\n",
                    paths.abbreviate(&h.file),
                    h.servers.join(" ")
                ));
            }
        }
        if !self.failed.is_empty() {
            out.push_str("\n回写失败:\n");
            for f in &self.failed {
                out.push_str(&format!("  {}  {}\n", paths.abbreviate(&f.file), f.reason));
            }
            out.push_str("旧 token 仍保留在 token 文件中，因此未回写成功的客户端不会掉线。\n");
        }
        if !self.skipped_project.is_empty() {
            out.push_str("\n项目作用域未写入 token:\n");
            for h in &self.skipped_project {
                out.push_str(&format!(
                    "  {}  {}  仍持有旧 token\n",
                    paths.abbreviate(&h.file),
                    h.servers.join(" ")
                ));
            }
        }

        if self.expired_old || self.expire_refused {
            out.push('\n');
            if self.would_break.is_empty() {
                out.push_str("没有仍持有旧 token 的客户端配置。\n");
            } else {
                out.push_str("将因失效旧 token 而无法认证的配置:\n");
                for h in &self.would_break {
                    out.push_str(&format!(
                        "  {}  {}\n",
                        paths.abbreviate(&h.file),
                        h.servers.join(" ")
                    ));
                }
            }
        }

        match (self.expired_old, self.expire_refused, self.previous_count) {
            (true, _, _) => {
                out.push_str("已失效旧 token：接受列表现在只剩当前这一份。\n");
            }
            (_, true, n) if n > 0 => {
                out.push_str(
                    "未加 --yes，拒绝失效旧 token。确认将断开的配置后重新运行：\n  vibrev token rotate --expire-old --yes\n",
                );
            }
            (false, false, n) if n > 0 => {
                out.push_str(
                    "\n确认所有客户端已切换后可运行 vibrev token rotate --expire-old --yes 失效旧 token。\n",
                );
            }
            _ => {}
        }
        out
    }
}

impl Hit {
    fn to_json(&self) -> Value {
        json!({
            "file": self.file.as_str(),
            "client": self.client,
            "scope": self.scope.as_str(),
            "servers": self.servers,
        })
    }
}

/// Never returns: every path ends in [`crate::ui::fail`] or `exit`.
pub fn run(opts: RotateOpts, paths: &Paths, json: bool) -> ! {
    let env = match Env::resolve() {
        Ok(e) => e,
        Err(e) => crate::ui::fail(json, "config", &format!("{e:#}"), &[]),
    };
    match rotate(paths, &env, opts.expire()) {
        Ok(report) => {
            if json {
                println!("{}", crate::pretty(&report.to_json()));
            } else {
                print!("{}", report.render(paths));
            }
            std::process::exit(if report.ok() { 0 } else { 1 })
        }
        Err(e) => crate::ui::fail(json, "token", &format!("{e:#}"), &[]),
    }
}

/// Rotate the shared token and rewrite vibrev-owned HTTP client configs.
///
/// The token file is updated *before* any client rewrite, with the previous
/// tokens still listed. That is what makes a later rewrite failure a visible
/// half-finished rotation rather than a bricked client.
pub fn rotate(paths: &Paths, env: &Env, expire: ExpireOld) -> Result<Report> {
    let token_file = token_file(paths);
    let _lock = atomic::lock(&token_file, paths)?;

    let loaded = shared::load_or_create(token_file.as_std_path()).map_err(describe)?;
    let previous = loaded.tokens;
    let current = shared::generate_distinct(&previous);
    let mut accepted = vec![current.clone()];
    accepted.extend(previous.iter().cloned());
    shared::write(token_file.as_std_path(), &accepted).map_err(describe)?;

    let mut rewritten = Vec::new();
    let mut failed = Vec::new();
    let mut skipped_project = Vec::new();

    for c in client::CLIENTS {
        for scope in Scope::ALL {
            let Some(file) = c.file(scope, env) else {
                continue;
            };
            if !file.exists() {
                continue;
            }
            match rewrite_file(c, scope, &file, paths, &previous, &current) {
                Ok(FileOutcome::Unchanged) => {}
                Ok(FileOutcome::Rewritten(hit)) => rewritten.push(hit),
                Ok(FileOutcome::SkippedProject(hit)) => skipped_project.push(hit),
                Err(reason) => failed.push(Fail {
                    file,
                    client: c.id,
                    scope,
                    reason,
                }),
            }
        }
    }

    let mut expired_old = false;
    let mut expire_refused = false;
    let mut would_break = Vec::new();
    match expire {
        ExpireOld::Keep => {}
        ExpireOld::Drop { confirmed } => {
            would_break = configs_still_on(env, &previous);
            if !confirmed {
                expire_refused = true;
            } else {
                shared::write(token_file.as_std_path(), std::slice::from_ref(&current))
                    .map_err(describe)?;
                expired_old = true;
            }
        }
    }

    Ok(Report {
        token_file,
        current,
        previous_count: previous.len(),
        previous_exposed: loaded
            .warnings
            .iter()
            .any(|warning| matches!(warning, shared::Warning::WorldReadable { .. })),
        rewritten,
        failed,
        skipped_project,
        would_break,
        expired_old,
        expire_refused,
    })
}

enum FileOutcome {
    Unchanged,
    Rewritten(Hit),
    SkippedProject(Hit),
}

fn rewrite_file(
    client: &Client,
    scope: Scope,
    file: &Utf8Path,
    paths: &Paths,
    old: &[String],
    new: &str,
) -> Result<FileOutcome, String> {
    let (_, mut doc) = mcpfile::read(file, client.format).map_err(|e| format!("{e:#}"))?;
    let matching: Vec<String> = doc
        .owned_http_bearers(client)
        .into_iter()
        .filter(|(_, tok)| old.iter().any(|o| o == tok))
        .map(|(name, _)| name)
        .collect();
    if matching.is_empty() {
        return Ok(FileOutcome::Unchanged);
    }

    let hit = Hit {
        file: file.to_owned(),
        client: client.id,
        scope,
        servers: matching.clone(),
    };

    // A project-scope file is what git commits. Replacing the old token with the
    // new one would leak the *current* credential into history.
    if scope.version_controlled() {
        return Ok(FileOutcome::SkippedProject(hit));
    }

    let _lock = atomic::lock(file, paths).map_err(|e| format!("{e:#}"))?;
    atomic::backup(file, false, paths).map_err(|e| format!("{e:#}"))?;
    let changed = doc.rewrite_owned_http_bearers(client, old, new);
    if changed.is_empty() {
        return Err("识别到旧 token 但未能改写 Authorization".to_owned());
    }
    atomic::write(file, &doc.render()).map_err(|e| format!("{e:#}"))?;
    Ok(FileOutcome::Rewritten(Hit {
        servers: changed,
        ..hit
    }))
}

/// Configs still carrying any of `old` after the rewrite pass — the list
/// `--expire-old` must show before it is allowed to drop those lines.
fn configs_still_on(env: &Env, old: &[String]) -> Vec<Hit> {
    let mut hits = Vec::new();
    for c in client::CLIENTS {
        for scope in Scope::ALL {
            let Some(file) = c.file(scope, env) else {
                continue;
            };
            if !file.exists() {
                continue;
            }
            let Ok((_, doc)) = mcpfile::read(&file, c.format) else {
                hits.push(Hit {
                    file,
                    client: c.id,
                    scope,
                    servers: vec!["(无法解析)".to_owned()],
                });
                continue;
            };
            let servers: Vec<String> = doc
                .owned_http_bearers(c)
                .into_iter()
                .filter(|(_, tok)| old.iter().any(|o| o == tok))
                .map(|(name, _)| name)
                .collect();
            if !servers.is_empty() {
                hits.push(Hit {
                    file,
                    client: c.id,
                    scope,
                    servers,
                });
            }
        }
    }
    hits
}

/// The current bearer, creating the file on first use.
///
/// `install` writes this into global HTTP entries so the client can talk to a
/// listener the operator started. The file is the same one `rotate` and every
/// engine open.
pub fn current(paths: &Paths) -> Result<String> {
    let file = token_file(paths);
    let loaded = shared::load_or_create(file.as_std_path()).map_err(describe)?;
    loaded
        .tokens
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("token 文件为空：{}", file))
}

/// The shared token file under this installation's root.
///
/// `paths.root` is itself `vibrev_kit::token::dir`, so the path an engine
/// resolves on its own and the path rotated here are the same one — including
/// under `VIBREV_HOME`, which they disagreed about until the rule moved to the
/// kit.
fn token_file(paths: &Paths) -> Utf8PathBuf {
    paths.root.join(shared::FILE_NAME)
}

/// Restate the kit's error in this program's language.
///
/// The kit is shared with two engines whose whole interface is English; this
/// binary's is not. Localisation is the one thing that should *not* be shared,
/// so the variants come across the boundary and the sentences are written here.
fn describe(error: TokenError) -> anyhow::Error {
    // The two variants that carry no `io::Error` say the whole thing in one
    // sentence; the rest want the operating system's own words kept as the cause.
    let context = match &error {
        TokenError::Empty { path } => {
            return anyhow::anyhow!("token 文件 {} 是空的；至少需要一行 token", path.display());
        }
        TokenError::NoHome => {
            return anyhow::anyhow!("无法定位用户主目录；请设置 HOME 或 VIBREV_HOME");
        }
        TokenError::Read { path, .. } => format!("读取 token 文件 {} 失败", path.display()),
        TokenError::Create { path, .. } => format!("创建 token 文件 {} 失败", path.display()),
        TokenError::CreateDir { path, .. } => format!("创建目录 {} 失败", path.display()),
        TokenError::Write { path, .. } => format!("写入 token 文件 {} 失败", path.display()),
    };
    anyhow::Error::new(error).context(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::scratch;

    fn setup(tag: &str) -> (Paths, Env, Utf8PathBuf) {
        let root = scratch(tag);
        let home = root.join("home");
        let cwd = root.join("proj");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&cwd).unwrap();
        let env = Env {
            home: home.clone(),
            app_config: home.join(".config"),
            cwd,
        };
        let paths = Paths {
            root: root.join("vibrev"),
            home: Some(home),
        };
        std::fs::create_dir_all(&paths.root).unwrap();
        (paths, env, root)
    }

    fn seed_token(paths: &Paths, tokens: &[&str]) -> String {
        let path = token_file(paths);
        let tokens: Vec<String> = tokens.iter().map(|t| (*t).to_owned()).collect();
        shared::write(path.as_std_path(), &tokens).unwrap();
        path.to_string()
    }

    fn http_entry(token: &str) -> String {
        format!(
            r#"{{
  "mcpServers": {{
    "vibrev-ida": {{
      "type": "http",
      "url": "http://127.0.0.1:8745/mcp",
      "headers": {{ "Authorization": "Bearer {token}" }}
    }},
    "sentry": {{
      "type": "http",
      "url": "https://mcp.sentry.dev/mcp",
      "headers": {{ "Authorization": "Bearer their_token" }}
    }}
  }}
}}
"#
        )
    }

    fn read_tokens(paths: &Paths) -> Vec<String> {
        shared::parse(&std::fs::read_to_string(token_file(paths)).unwrap())
    }

    #[test]
    fn new_token_is_first_and_old_is_retained() {
        let (paths, env, _) = setup("token-retain");
        seed_token(&paths, &["vbr_OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOL"]);

        let report = rotate(&paths, &env, ExpireOld::Keep).unwrap();
        assert!(
            report.current.starts_with(shared::PREFIX),
            "{}",
            report.current
        );
        assert_ne!(report.current, "vbr_OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOL");

        let tokens = read_tokens(&paths);
        assert_eq!(tokens[0], report.current);
        assert_eq!(tokens[1], "vbr_OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOL");
        assert!(report.ok());
        assert!(!report.expired_old);
    }

    #[test]
    fn a_global_http_entry_is_rewritten_to_the_new_token() {
        let (paths, env, _) = setup("token-rewrite-global");
        seed_token(&paths, &["vbr_OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOL"]);
        let cfg = env.home.join(".claude.json");
        std::fs::write(&cfg, http_entry("vbr_OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOL")).unwrap();

        let report = rotate(&paths, &env, ExpireOld::Keep).unwrap();
        assert!(report.ok(), "{report:?}");
        assert_eq!(report.rewritten.len(), 1);
        assert_eq!(report.rewritten[0].servers, ["vibrev-ida"]);

        let after = std::fs::read_to_string(&cfg).unwrap();
        assert!(
            after.contains(&format!("Bearer {}", report.current)),
            "{after}"
        );
        assert!(
            !after.contains("vbr_OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOL"),
            "{after}"
        );
        assert!(
            after.contains("their_token"),
            "foreign entry was touched:\n{after}"
        );

        let tokens = read_tokens(&paths);
        assert_eq!(tokens[1], "vbr_OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOL");
    }

    #[test]
    fn a_failed_rewrite_does_not_drop_the_old_token() {
        let (paths, env, _) = setup("token-rewrite-fail");
        seed_token(&paths, &["vbr_OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOL"]);
        // A directory where a file should be: read fails, so the rewrite does.
        std::fs::create_dir_all(env.home.join(".claude.json")).unwrap();

        let report = rotate(&paths, &env, ExpireOld::Keep).unwrap();
        assert!(!report.ok());
        assert!(!report.failed.is_empty());
        let tokens = read_tokens(&paths);
        assert_eq!(tokens[0], report.current);
        assert!(
            tokens.contains(&"vbr_OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOL".to_owned()),
            "{tokens:?}"
        );
        assert!(!report.expired_old);
    }

    #[test]
    fn expire_old_without_yes_refuses_and_keeps_old_tokens() {
        let (paths, env, _) = setup("token-expire-refuse");
        seed_token(&paths, &["vbr_OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOL"]);

        let report = rotate(&paths, &env, ExpireOld::Drop { confirmed: false }).unwrap();
        assert!(report.expire_refused);
        assert!(!report.ok());
        assert!(!report.expired_old);
        let tokens = read_tokens(&paths);
        assert_eq!(tokens[0], report.current);
        assert!(
            tokens.contains(&"vbr_OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOL".to_owned()),
            "{tokens:?}"
        );
    }

    #[test]
    fn project_scope_does_not_gain_a_token() {
        let (paths, env, _) = setup("token-project-skip");
        seed_token(&paths, &["vbr_OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOL"]);
        let proj = env.cwd.join(".mcp.json");
        std::fs::write(&proj, http_entry("vbr_OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOL")).unwrap();

        let report = rotate(&paths, &env, ExpireOld::Keep).unwrap();
        assert!(report.rewritten.is_empty());
        assert_eq!(report.skipped_project.len(), 1);
        let after = std::fs::read_to_string(&proj).unwrap();
        assert!(
            after.contains("vbr_OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOL"),
            "project file was rewritten:\n{after}"
        );
        assert!(!after.contains(&report.current), "{after}");
    }

    #[test]
    fn expire_old_with_yes_drops_previous_lines() {
        let (paths, env, _) = setup("token-expire-yes");
        seed_token(&paths, &["vbr_OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOL"]);

        let report = rotate(&paths, &env, ExpireOld::Drop { confirmed: true }).unwrap();
        assert!(report.expired_old);
        assert!(report.ok());
        let tokens = read_tokens(&paths);
        assert_eq!(tokens, [report.current]);
    }

    #[cfg(unix)]
    #[test]
    fn generated_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (paths, env, _) = setup("token-mode");
        rotate(&paths, &env, ExpireOld::Keep).unwrap();
        let mode = std::fs::metadata(token_file(&paths))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    /// A token file anyone on the host could read means the token being rotated
    /// away from has to be assumed leaked, and `--expire-old` stops being a
    /// tidiness step. The rotation repairs the mode on its way past, so unless
    /// this is said now nobody ever finds out it was wrong.
    #[cfg(unix)]
    #[test]
    fn a_world_readable_file_is_called_out_before_it_is_repaired() {
        use std::os::unix::fs::PermissionsExt;
        let (paths, env, _) = setup("token-exposed");
        seed_token(&paths, &["vbr_OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOL"]);
        let path = token_file(&paths);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let report = rotate(&paths, &env, ExpireOld::Keep).unwrap();
        assert!(report.previous_exposed);
        assert!(report.render(&paths).contains("旧 token 应视为已泄漏"));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "and the file itself is repaired");

        let clean = rotate(&paths, &env, ExpireOld::Keep).unwrap();
        assert!(!clean.previous_exposed);
    }
}
