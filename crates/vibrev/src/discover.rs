//! Engine binary discovery — four levels, first hit wins.
//!
//! 1. `[engines.<id>] path` in `~/.vibrev/config.toml`
//! 2. `~/.vibrev/engines/<bin>[.exe]`
//! 3. `PATH`
//! 4. nothing — the caller prints [`crate::engine::Engine::install`]
//!
//! Level 1 does *not* fall through. If a user wrote down where the binary is and
//! it is not there, that is a mistake worth surfacing; silently dropping to `PATH`
//! would hand them a different binary than the one they asked for.

use camino::{Utf8Path, Utf8PathBuf};

use crate::config::{Config, Paths, expand_tilde};
use crate::engine::Engine;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Config,
    Convention,
    Path,
}

impl Origin {
    /// The origin column in `doctor`'s table.
    pub fn label(self, paths: &Paths, path: &Utf8Path) -> String {
        match self {
            Origin::Path => "PATH".to_owned(),
            Origin::Config | Origin::Convention => paths.abbreviate(path),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Origin::Config => "config",
            Origin::Convention => "convention",
            Origin::Path => "path",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Located {
    pub path: Utf8PathBuf,
    pub origin: Origin,
    /// Argv for the stdio-MCP handshake, after any `config.toml` override.
    pub mcp_args: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum Outcome {
    Found(Located),
    /// Not configured and not on disk anywhere we looked.
    Missing,
    /// `config.toml` named a path that is not a runnable file.
    ConfigBroken {
        path: Utf8PathBuf,
        reason: String,
    },
}

pub fn locate(engine: &'static Engine, cfg: &Config, paths: &Paths) -> Outcome {
    let entry = cfg.engines.get(engine.id);
    let mcp_args = entry
        .and_then(|e| e.mcp_args.clone())
        .unwrap_or_else(|| engine.mcp_args.iter().map(|s| (*s).to_owned()).collect());

    // 1. Explicit configuration.
    if let Some(raw) = entry.and_then(|e| e.path.as_deref()) {
        let path = expand_tilde(raw, paths);
        return match runnable(&path) {
            Ok(()) => Outcome::Found(Located {
                path,
                origin: Origin::Config,
                mcp_args,
            }),
            Err(reason) => Outcome::ConfigBroken { path, reason },
        };
    }

    // 2. The convention directory.
    let dir = paths.engines_dir();
    for candidate in [
        dir.join(engine.bin),
        dir.join(format!("{}{}", engine.bin, EXE_SUFFIX)),
    ] {
        if runnable(&candidate).is_ok() {
            return Outcome::Found(Located {
                path: candidate,
                origin: Origin::Convention,
                mcp_args,
            });
        }
    }

    // 3. PATH.
    if let Ok(found) = which::which(engine.bin)
        && let Ok(path) = Utf8PathBuf::from_path_buf(found)
    {
        return Outcome::Found(Located {
            path,
            origin: Origin::Path,
            mcp_args,
        });
    }

    // 4. Nothing.
    Outcome::Missing
}

/// Discover every engine in registry order.
pub fn locate_all(cfg: &Config, paths: &Paths) -> Vec<(&'static Engine, Outcome)> {
    crate::engine::ENGINES
        .iter()
        .map(|e| (e, locate(e, cfg, paths)))
        .collect()
}

#[cfg(windows)]
const EXE_SUFFIX: &str = ".exe";
#[cfg(not(windows))]
const EXE_SUFFIX: &str = "";

/// Exists, is a file, and (on Unix) carries an execute bit. The Unix check matters:
/// a `cargo build` output copied with `cp -p` keeps its mode, but a file dropped in
/// by an archive extractor may not, and `exec` would fail much later with EACCES.
fn runnable(path: &Utf8Path) -> Result<(), String> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err("文件不存在".to_owned()),
        Err(e) => return Err(e.to_string()),
    };
    if !meta.is_file() {
        return Err("不是普通文件".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 == 0 {
            return Err("没有可执行权限".to_owned());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EngineConfig;

    fn paths_in(root: &Utf8Path) -> Paths {
        Paths {
            root: root.to_owned(),
            home: Some(root.to_owned()),
        }
    }

    fn touch_exec(path: &Utf8Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    /// Scratch space next to the test binary, i.e. inside `target/`. Deliberately
    /// not `std::env::temp_dir()`: `/tmp` is a small tmpfs on the dev machines.
    fn scratch(tag: &str) -> Utf8PathBuf {
        let exe = std::env::current_exe().unwrap();
        let base = Utf8PathBuf::from_path_buf(exe.parent().unwrap().to_owned())
            .unwrap()
            .join("vibrev-test-scratch")
            .join(tag);
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn convention_dir_beats_path() {
        let root = scratch("convention");
        let engine = crate::engine::by_id("jadx").unwrap();
        touch_exec(&root.join("engines").join(engine.bin));

        let out = locate(engine, &Config::default(), &paths_in(&root));
        match out {
            Outcome::Found(l) => {
                assert_eq!(l.origin, Origin::Convention);
                assert_eq!(l.path, root.join("engines").join("rjadx"));
                assert_eq!(l.mcp_args, ["mcp", "--stdio"]);
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn a_broken_config_path_does_not_fall_through() {
        let root = scratch("broken");
        let engine = crate::engine::by_id("ida").unwrap();
        // A convention-dir binary exists, so a fall-through would succeed — and
        // would be wrong, because the user named a different file.
        touch_exec(&root.join("engines").join(engine.bin));

        let mut cfg = Config::default();
        cfg.engines.insert(
            "ida".to_owned(),
            EngineConfig {
                path: Some(root.join("nope").to_string()),
                mcp_args: None,
            },
        );

        match locate(engine, &cfg, &paths_in(&root)) {
            Outcome::ConfigBroken { reason, .. } => assert_eq!(reason, "文件不存在"),
            other => panic!("expected ConfigBroken, got {other:?}"),
        }
    }

    #[test]
    fn config_supplies_both_the_path_and_the_probe_argv() {
        let root = scratch("cfg-args");
        let engine = crate::engine::by_id("bn").unwrap();
        let bin = root.join("custom-bn");
        touch_exec(&bin);

        let mut cfg = Config::default();
        cfg.engines.insert(
            "bn".to_owned(),
            EngineConfig {
                path: Some(bin.to_string()),
                mcp_args: Some(vec!["mcp".to_owned()]),
            },
        );

        match locate(engine, &cfg, &paths_in(&root)) {
            Outcome::Found(l) => {
                assert_eq!(l.origin, Origin::Config);
                assert_eq!(l.mcp_args, ["mcp"]);
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn nothing_anywhere_is_missing_not_an_error() {
        let root = scratch("missing");
        let engine = crate::engine::by_id("bn").unwrap();
        assert!(matches!(
            locate(engine, &Config::default(), &paths_in(&root)),
            Outcome::Missing
        ));
    }
}
