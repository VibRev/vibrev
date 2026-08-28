//! `~/.vibrev` — where the config file and the convention directory live.
//!
//! `etcetera::home_dir()` rather than `dirs`/`directories` (both archived) — it is
//! a thin wrapper over `std::env::home_dir()`, un-deprecated in Rust 1.87.
//! `VIBREV_HOME` overrides the root, which is also what makes this testable
//! without writing into a real user's home.
//!
//! Finding home is ours; the *rule* is not. One file in this directory — the
//! bearer token — is also opened by an engine in another repository, so
//! `VIBREV_HOME` has to be resolved through `vibrev_kit::token` and nowhere
//! else. Should the two ever disagree, setting it would rotate one file while
//! the listener read another, and every client would get a 401 out of a rotation
//! that reported success.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use serde::Deserialize;

/// The `~/.vibrev` tree.
#[derive(Debug, Clone)]
pub struct Paths {
    pub root: Utf8PathBuf,
    /// Where `home_dir()` said home was; used to abbreviate paths back to `~/…`.
    pub home: Option<Utf8PathBuf>,
}

impl Paths {
    pub fn resolve() -> Result<Self> {
        let home = etcetera::home_dir()
            .ok()
            .and_then(|p| Utf8PathBuf::from_path_buf(p).ok());

        let root = vibrev_kit::token::dir(home.as_deref().map(Utf8Path::as_std_path))
            .context("无法定位用户主目录；请设置 HOME 或 VIBREV_HOME")?;
        let root = Utf8PathBuf::from_path_buf(root)
            .map_err(|p| anyhow::anyhow!("vibrev 根目录不是有效的 UTF-8 路径: {}", p.display()))?;

        Ok(Self { root, home })
    }

    pub fn config_file(&self) -> Utf8PathBuf {
        self.root.join("config.toml")
    }

    pub fn engines_dir(&self) -> Utf8PathBuf {
        self.root.join("engines")
    }

    /// `~/.vibrev/engines/rjadx` reads better in a table than the absolute path.
    pub fn abbreviate(&self, p: &Utf8Path) -> String {
        match &self.home {
            Some(home) => match p.strip_prefix(home) {
                Ok(rest) => format!("~/{rest}"),
                Err(_) => p.to_string(),
            },
            None => p.to_string(),
        }
    }
}

/// `~/.vibrev/config.toml`.
///
/// ```toml
/// [engines.ida]
/// path = "~/build/ida-headless-mcp"
/// mcp_args = ["serve", "--mode", "stdio"]
/// ```
#[derive(Debug, Default, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub engines: BTreeMap<String, EngineConfig>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct EngineConfig {
    /// Explicit binary location. `~` is expanded.
    pub path: Option<String>,
    /// Overrides [`crate::engine::Engine::mcp_args`] for the identity probe.
    pub mcp_args: Option<Vec<String>>,
}

/// Missing file is not an error — most users will never write one.
pub fn load(paths: &Paths) -> Result<Config> {
    let file = paths.config_file();
    let raw = match std::fs::read_to_string(&file) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(e) => return Err(e).with_context(|| format!("读取 {file} 失败")),
    };
    toml::from_str(&raw).with_context(|| format!("解析 {file} 失败"))
}

/// Expand a leading `~` against the resolved home directory. Only a leading `~/`
/// (or a bare `~`) is special; `~user` is not supported and is left alone, which
/// fails loudly at the existence check rather than silently resolving elsewhere.
pub fn expand_tilde(raw: &str, paths: &Paths) -> Utf8PathBuf {
    let Some(home) = &paths.home else {
        return Utf8PathBuf::from(raw);
    };
    if raw == "~" {
        return home.clone();
    }
    match raw.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None => Utf8PathBuf::from(raw),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> Paths {
        Paths {
            root: Utf8PathBuf::from("/home/u/.vibrev"),
            home: Some(Utf8PathBuf::from("/home/u")),
        }
    }

    #[test]
    fn tilde_expands_only_at_the_front() {
        assert_eq!(expand_tilde("~/bin/x", &paths()), "/home/u/bin/x");
        assert_eq!(expand_tilde("~", &paths()), "/home/u");
        assert_eq!(expand_tilde("/opt/~/x", &paths()), "/opt/~/x");
        assert_eq!(expand_tilde("~root/x", &paths()), "~root/x");
    }

    #[test]
    fn paths_under_home_display_abbreviated() {
        let p = paths();
        assert_eq!(
            p.abbreviate(Utf8Path::new("/home/u/.vibrev/engines/rjadx")),
            "~/.vibrev/engines/rjadx"
        );
        assert_eq!(
            p.abbreviate(Utf8Path::new("/usr/bin/rjadx")),
            "/usr/bin/rjadx"
        );
    }

    #[test]
    fn config_parses_the_documented_shape() {
        let cfg: Config = toml::from_str(
            r#"
            [engines.ida]
            path = "~/build/ida-headless-mcp"
            mcp_args = ["serve", "--mode", "stdio"]

            [engines.jadx]
            path = "/usr/bin/rjadx"
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg.engines["ida"].mcp_args.as_deref(),
            Some(&["serve".to_owned(), "--mode".to_owned(), "stdio".to_owned()][..])
        );
        assert!(cfg.engines["jadx"].mcp_args.is_none());
    }
}
