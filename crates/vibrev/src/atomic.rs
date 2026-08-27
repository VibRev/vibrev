//! Getting a modified config file onto disk without ever being able to lose one.
//!
//! These files belong to the user and are read (and rewritten) by a long-running
//! client at unpredictable times, which forces three separate mechanisms:
//!
//! * **Atomic replace.** Write a sibling temp file, fsync it, `rename` it over the
//!   target. `rename(2)` within a directory is atomic, so a client reading
//!   concurrently sees either the old file or the new one — never a truncated one.
//!   This is what actually protects against the clients, none of which lock.
//! * **Advisory lock.** Serialises `vibrev` against itself, e.g. two `install`
//!   runs writing `~/.claude.json` from different terminals.
//! * **`.bak`.** A one-time escape hatch that captures the file as it was before
//!   `vibrev` ever touched it. Always `0600`, and **not a sibling of the target
//!   when the target is version-controlled** — see [`backup_path`].

use std::fs::File;
use std::io::Write;

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use fs4::FileExt;

use crate::config::Paths;

/// Held for the duration of a file's read-modify-write. Releases on drop.
pub struct Lock {
    file: File,
}

impl Drop for Lock {
    fn drop(&mut self) {
        // Closing the handle releases the flock anyway; being explicit keeps the
        // failure visible in a debugger rather than silently deferred.
        let _ = FileExt::unlock(&self.file);
    }
}

/// Take an exclusive advisory lock covering `target`.
///
/// The lock lives in `~/.vibrev/locks/`, not next to the target. Locking the
/// target itself would be self-defeating: we replace it by `rename`, so a waiter
/// blocked on the old inode would wake up holding a lock on an unlinked file and
/// then read a stale copy. A path that is only ever locked, never replaced, has no
/// such window — and it keeps `.lock` clutter out of the user's home.
pub fn lock(target: &Utf8Path, paths: &Paths) -> Result<Lock> {
    let dir = paths.root.join("locks");
    std::fs::create_dir_all(&dir).with_context(|| format!("创建 {dir} 失败"))?;

    let path = dir.join(format!("{}.lock", sanitize(target)));
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("打开锁文件 {path} 失败"))?;

    // Try first so that a wait can be explained. Blocking silently on a lock some
    // other terminal is holding looks exactly like a hang.
    if FileExt::try_lock(&file).is_err() {
        eprintln!("等待 {target} 的写锁（另一个 vibrev 正在写入）…");
        FileExt::lock(&file).with_context(|| format!("获取 {target} 的写锁失败"))?;
    }
    Ok(Lock { file })
}

/// A filesystem-safe, collision-free stand-in for an absolute path.
///
/// Every non-alphanumeric byte becomes `_`, which is lossy, so the full path is
/// appended as a hash to keep `~/.cursor/mcp.json` and `~/.vscode/mcp.json` apart.
fn sanitize(path: &Utf8Path) -> String {
    let mut s: String = path
        .as_str()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    // Keep the name short enough for every filesystem's 255-byte limit while
    // leaving the tail (the distinctive part) visible.
    if s.len() > 80 {
        s = s[s.len() - 80..].to_owned();
    }
    format!("{s}-{:016x}", fnv1a(path.as_str()))
}

/// FNV-1a, inline rather than pulled in: this names a lock file, it is not a
/// security or collision-critical hash.
fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// What [`backup`] did, for the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backup {
    /// Written just now.
    Created(Utf8PathBuf),
    /// One was already there and was left alone — it predates this run and is
    /// therefore the more valuable copy. Overwriting it would destroy the only
    /// record of the file before `vibrev` first touched it.
    Kept(Utf8PathBuf),
    /// The target does not exist yet, so there is nothing to back up.
    NotNeeded,
}

/// Where `target`'s `.bak` goes.
///
/// Normally right beside the file, which is where a user looks for it. **Except
/// when the file is version-controlled**: a sibling `.bak` inside the repository
/// is an untracked, unignored copy of the very file we are sanitising, so a
/// `git add .` commits the secret we just removed — the leak moves from a file
/// the user was warned about to one they will never think to look at. Those
/// backups go to `~/.vibrev/backups/` instead, keyed by the same sanitised path
/// used for locks.
///
/// Note this is about the *directory being committed*, not about whether the
/// content is sensitive: we do not want to be in the business of deciding which
/// of the user's config files are secret.
pub fn backup_path(target: &Utf8Path, in_repo: bool, paths: &Paths) -> Utf8PathBuf {
    if in_repo {
        paths
            .root
            .join("backups")
            .join(format!("{}.bak", sanitize(target)))
    } else {
        Utf8PathBuf::from(format!("{target}.bak"))
    }
}

/// Copy `target` aside, once ever.
///
/// `in_repo` says the target lives in a directory that gets committed; see
/// [`backup_path`]. The copy is always `0600` — it is a private duplicate of a
/// config file, there is no reader for it but its owner, and the mode is set **at
/// creation** rather than by a later `chmod` so there is no window in which it is
/// world-readable.
pub fn backup(target: &Utf8Path, in_repo: bool, paths: &Paths) -> Result<Backup> {
    if !target.exists() {
        return Ok(Backup::NotNeeded);
    }
    let bak = backup_path(target, in_repo, paths);
    if let Some(dir) = bak.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("创建 {dir} 失败"))?;
    }
    if bak.exists() {
        return Ok(Backup::Kept(bak));
    }
    // `create_new` rather than a check-then-copy: it is the same guarantee without
    // the race, and it fails loudly if someone wins it.
    let mut opts = File::options();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut out = match opts.open(&bak) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(Backup::Kept(bak)),
        Err(e) => return Err(e).with_context(|| format!("创建备份 {bak} 失败")),
    };
    let data = std::fs::read(target).with_context(|| format!("读取 {target} 失败"))?;
    out.write_all(&data)
        .and_then(|()| out.sync_all())
        .with_context(|| format!("写入备份 {bak} 失败"))?;
    Ok(Backup::Created(bak))
}

/// Replace `target`'s contents with `content`, atomically.
pub fn write(target: &Utf8Path, content: &str) -> Result<()> {
    let dir = target
        .parent()
        .filter(|p| !p.as_str().is_empty())
        .unwrap_or(Utf8Path::new("."));
    std::fs::create_dir_all(dir).with_context(|| format!("创建目录 {dir} 失败"))?;

    // Same directory, so the rename below cannot become a cross-device copy.
    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("在 {dir} 创建临时文件失败"))?;
    tmp.write_all(content.as_bytes())
        .and_then(|()| tmp.flush())
        .and_then(|()| tmp.as_file().sync_all())
        .with_context(|| format!("写入 {target} 的临时文件失败"))?;

    // tempfile creates 0600. Right for a file we are introducing, wrong for one
    // the user already had — inherit their mode instead of tightening it silently.
    #[cfg(unix)]
    if let Ok(meta) = std::fs::metadata(target) {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        let _ = tmp
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(mode));
    }

    tmp.persist(target)
        .map_err(|e| e.error)
        .with_context(|| format!("替换 {target} 失败"))?;

    // The rename is only durable once the directory entry itself is synced;
    // best-effort, since not every filesystem lets you open a directory.
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::scratch;

    fn paths_in(dir: &Utf8Path) -> Paths {
        Paths {
            root: dir.join("vibrev"),
            home: Some(dir.to_owned()),
        }
    }

    #[test]
    fn backup_is_created_once_and_then_never_clobbered() {
        let dir = scratch("atomic-backup");
        let paths = paths_in(&dir);
        let target = dir.join("mcp.json");
        std::fs::write(&target, "original\n").unwrap();

        let first = backup(&target, false, &paths).unwrap();
        assert_eq!(first, Backup::Created(dir.join("mcp.json.bak")));
        assert_eq!(
            std::fs::read_to_string(dir.join("mcp.json.bak")).unwrap(),
            "original\n"
        );

        // A later run changes the file, then backs up again.
        write(&target, "second\n").unwrap();
        let second = backup(&target, false, &paths).unwrap();
        assert_eq!(second, Backup::Kept(dir.join("mcp.json.bak")));
        assert_eq!(
            std::fs::read_to_string(dir.join("mcp.json.bak")).unwrap(),
            "original\n",
            ".bak must still hold the pre-vibrev content"
        );
    }

    #[test]
    fn nothing_to_back_up_is_not_an_error() {
        let dir = scratch("atomic-nobackup");
        let paths = paths_in(&dir);
        assert_eq!(
            backup(&dir.join("absent.json"), false, &paths).unwrap(),
            Backup::NotNeeded
        );
        assert!(!dir.join("absent.json.bak").exists());
    }

    #[test]
    fn a_version_controlled_backup_lands_outside_the_repository() {
        // The whole point: a sibling `.bak` is an untracked copy of the file we
        // just sanitised, and `git add .` would commit it.
        let dir = scratch("atomic-backup-repo");
        let paths = paths_in(&dir);
        let target = dir.join("repo").join(".mcp.json");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, "secret\n").unwrap();

        let Backup::Created(bak) = backup(&target, true, &paths).unwrap() else {
            panic!("a backup should have been created");
        };
        assert!(
            !dir.join("repo").join(".mcp.json.bak").exists(),
            "nothing beside the target"
        );
        assert!(bak.starts_with(paths.root.join("backups")), "went to {bak}");
        assert_eq!(std::fs::read_to_string(&bak).unwrap(), "secret\n");

        // Still exactly once, from the new location.
        assert_eq!(backup(&target, true, &paths).unwrap(), Backup::Kept(bak));
    }

    #[cfg(unix)]
    #[test]
    fn backups_are_private_regardless_of_the_originals_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("atomic-backup-mode");
        let paths = paths_in(&dir);
        let target = dir.join("mcp.json");
        std::fs::write(&target, "tokenish\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();

        let Backup::Created(bak) = backup(&target, false, &paths).unwrap() else {
            panic!("a backup should have been created");
        };
        let mode = std::fs::metadata(&bak).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a copy of a config file has no other reader");
    }

    #[test]
    fn write_creates_missing_parents_and_replaces_atomically() {
        let dir = scratch("atomic-write");
        let target = dir.join("deep").join("nested").join("mcp.json");
        write(&target, "{}\n").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "{}\n");

        write(&target, "{\"a\":1}\n").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "{\"a\":1}\n");
        // No temp files left behind.
        let leftovers: Vec<_> = std::fs::read_dir(target.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != "mcp.json")
            .collect();
        assert!(leftovers.is_empty(), "unexpected files: {leftovers:?}");
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_files_mode_is_preserved() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("atomic-mode");
        let target = dir.join("mcp.json");
        std::fs::write(&target, "{}").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();

        write(&target, "{\"a\":1}").unwrap();
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn locks_are_per_target_and_released_on_drop() {
        let dir = scratch("atomic-lock");
        let paths = Paths {
            root: dir.join("vibrev"),
            home: Some(dir.clone()),
        };
        let a = dir.join("a.json");
        let b = dir.join("b.json");

        // Two different targets are lockable at once: one busy client config must
        // not stall an unrelated one.
        let la = lock(&a, &paths).unwrap();
        let lb = lock(&b, &paths).unwrap();
        let names: Vec<String> = std::fs::read_dir(paths.root.join("locks"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 2, "one lock file per target: {names:?}");
        drop(la);
        drop(lb);

        // And the same target is lockable again once released.
        let _again = lock(&a, &paths).unwrap();
    }

    #[test]
    fn sanitized_names_stay_distinct_for_similar_paths() {
        let x = sanitize(Utf8Path::new("/home/u/.cursor/mcp.json"));
        let y = sanitize(Utf8Path::new("/home/u/.vscode/mcp.json"));
        assert_ne!(x, y);
        assert!(x.len() < 120);
        assert!(
            x.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        );
    }
}
