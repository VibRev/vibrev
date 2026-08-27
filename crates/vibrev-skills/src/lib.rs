//! Agent skills: what an engine knows that its tool surface cannot say.
//!
//! A skill is a directory of Markdown that teaches a model something no tool
//! signature conveys — `ida-headless-mcp` ships 105 files of IDAPython
//! reference. The engine ships as one executable, so the repository directory
//! reaches nobody: a build script compresses the tree into the binary and the
//! binary writes it back out on request.
//!
//! # Why this is a crate and not engine code
//!
//! Two programs that cannot see each other's source have to agree on what
//! `skills list --json` says. `vibrev install` runs an engine it merely found
//! on disk, reads that document, compares a fingerprint against a marker file,
//! and decides whether to write into someone's home directory.
//!
//! [`Skill`] is the one type on both ends of that exchange. Same rule as
//! `vibrev_kit::token`: this crate holds *anything two VibRev programs have to
//! agree on*, not just what engines share.
//!
//! # Why it is not `vibrev-kit::skills`
//!
//! A build script has to call [`pack::pack`], and `vibrev-kit` pulls in rmcp,
//! tokio and schemars. Making an engine's `build.rs` compile an MCP server
//! library for the host to read some Markdown is a real cost on every clean
//! build, paid by every engine. This crate's `runtime` feature (on by default,
//! off for build scripts) is the same line `vibrev-kit` draws around axum.
//!
//! # Shape
//!
//! ```text
//! build.rs                 vibrev_skills::pack::pack(&root)?   -> OUT_DIR
//! src/skills.rs            vibrev_skills::embedded!()          -> Embedded
//! main.rs                  args.run(&SKILLS, name, version)    -> the two verbs
//! ```
//!
//! Nothing here touches a disassembler. `skills list` and `skills export` are
//! answerable with no database, no license and no analysis backend installed,
//! which is exactly what lets an installer ask a binary what it offers before
//! deciding anything.

mod archive;
pub mod pack;

#[cfg(feature = "runtime")]
mod cli;
#[cfg(feature = "runtime")]
mod wire;

#[cfg(feature = "runtime")]
pub use cli::{SkillsArgs, command, from_matches};
#[cfg(feature = "runtime")]
pub use wire::{Listing, Skill};

use std::path::{Component, Path, PathBuf};

/// One skill, as the build script found it in `skills/`.
///
/// Every field is `'static` because the whole table is generated into the
/// binary — see [`embedded!`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkillMeta {
    /// Directory name, which is also the frontmatter `name:` — the build fails
    /// if the two disagree.
    pub name: &'static str,
    pub description: &'static str,
    pub files: usize,
    /// Uncompressed size of every file in the skill.
    pub bytes: usize,
    /// FNV-1a over the sorted `(path, contents)` sequence, 16 hex digits.
    ///
    /// Opaque to everyone who reads it: the only operation is equality against
    /// what an installer recorded on disk, which is what makes "already up to
    /// date" cheap. See `archive::fingerprint` for why it is not a
    /// cryptographic hash.
    pub fingerprint: &'static str,
}

/// The skills compiled into one engine binary.
///
/// Built by [`embedded!`] and stored in a `static`, so an engine that ships no
/// skills carries an empty table and a well-formed empty archive rather than a
/// special case.
pub struct Embedded {
    skills: &'static [SkillMeta],
    archive: &'static [u8],
}

impl Embedded {
    pub const fn new(skills: &'static [SkillMeta], archive: &'static [u8]) -> Self {
        Self { skills, archive }
    }

    /// Every skill this binary ships, sorted by name.
    pub fn all(&self) -> &'static [SkillMeta] {
        self.skills
    }

    pub fn by_name(&self, name: &str) -> Option<&'static SkillMeta> {
        self.skills.iter().find(|s| s.name == name)
    }

    fn names(&self) -> Vec<&'static str> {
        self.skills.iter().map(|s| s.name).collect()
    }

    /// Unpack `only` (or every skill) into `dir`, one subdirectory per skill.
    ///
    /// Existing files are overwritten: the caller that matters — an installer
    /// staging into a fresh temporary directory — has nothing to lose, and a
    /// user running this by hand into a stale directory wants the new copy.
    pub fn export(&self, dir: &Path, only: Option<&str>) -> Result<Vec<Exported>, ExportError> {
        let wanted: Vec<&'static SkillMeta> = match only {
            Some(name) => vec![
                self.by_name(name)
                    .ok_or_else(|| ExportError::UnknownSkill {
                        asked: name.to_owned(),
                        available: self.names().join(", "),
                    })?,
            ],
            None => self.skills.iter().collect(),
        };

        let entries = archive::read(self.archive)?;
        let mut out = Vec::new();
        for skill in wanted {
            let prefix = format!("{}/", skill.name);
            let mut files = Vec::new();
            for (path, body) in entries.iter().filter(|(p, _)| p.starts_with(&prefix)) {
                let target = safe_join(dir, path)?;
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent).map_err(|source| ExportError::Write {
                        path: parent.to_path_buf(),
                        source,
                    })?;
                }
                std::fs::write(&target, body).map_err(|source| ExportError::Write {
                    path: target.clone(),
                    source,
                })?;
                files.push(target);
            }
            if files.len() != skill.files {
                // The metadata table and the archive are generated from one
                // walk of one directory, so a mismatch means the two came from
                // different builds — a stale `OUT_DIR`, or an archive edited in
                // place.
                return Err(ExportError::CountMismatch {
                    skill: skill.name,
                    unpacked: files.len(),
                    claimed: skill.files,
                });
            }
            out.push(Exported {
                skill,
                root: dir.join(skill.name),
                files,
            });
        }
        Ok(out)
    }
}

/// What [`Embedded::export`] wrote.
#[derive(Debug, Clone)]
pub struct Exported {
    pub skill: &'static SkillMeta,
    pub root: PathBuf,
    pub files: Vec<PathBuf>,
}

/// Why an export did not happen.
#[derive(Debug)]
pub enum ExportError {
    UnknownSkill {
        asked: String,
        available: String,
    },
    /// The archive did not parse — this binary's own build output is not what
    /// this code expects.
    Archive(archive::ArchiveError),
    /// A path in the archive would have landed outside the target directory.
    Traversal(String),
    CountMismatch {
        skill: &'static str,
        unpacked: usize,
        claimed: usize,
    },
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl From<archive::ArchiveError> for ExportError {
    fn from(error: archive::ArchiveError) -> Self {
        Self::Archive(error)
    }
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSkill { asked, available } => {
                write!(f, "no skill named '{asked}'; this binary ships {available}")
            }
            Self::Archive(error) => error.fmt(f),
            Self::Traversal(path) => write!(
                f,
                "refusing to write skill path '{path}': it escapes the target directory"
            ),
            Self::CountMismatch {
                skill,
                unpacked,
                claimed,
            } => write!(
                f,
                "skill '{skill}' unpacked {unpacked} files but its metadata claims {claimed}"
            ),
            Self::Write { path, source } => {
                write!(f, "failed to write {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for ExportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Archive(error) => Some(error),
            Self::Write { source, .. } => Some(source),
            Self::UnknownSkill { .. } | Self::Traversal(_) | Self::CountMismatch { .. } => None,
        }
    }
}

/// Join `rel` under `dir`, refusing anything that could land outside it.
///
/// The archive is produced by our own build script, so no path in it can fail
/// this today. The check stays because what sits on the other side is a
/// directory in the user's home, and "the input is trusted" is the assumption
/// that stops being true first.
fn safe_join(dir: &Path, rel: &str) -> Result<PathBuf, ExportError> {
    let candidate = Path::new(rel);
    let escapes = candidate
        .components()
        .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir));
    if escapes {
        return Err(ExportError::Traversal(rel.to_owned()));
    }
    Ok(dir.join(candidate))
}

/// Bind the two files [`pack::pack`] wrote into an [`Embedded`].
///
/// ```ignore
/// pub static SKILLS: vibrev_skills::Embedded = vibrev_skills::embedded!();
/// ```
///
/// `env!` and `include_bytes!` expand at the call site, so this reads the
/// *calling* crate's `OUT_DIR` — which is the only `OUT_DIR` that has anything
/// in it.
#[macro_export]
macro_rules! embedded {
    () => {
        $crate::Embedded::new(
            include!(concat!(env!("OUT_DIR"), "/skills_meta.rs")),
            include_bytes!(concat!(env!("OUT_DIR"), "/skills.bin")),
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_paths_are_refused() {
        let dir = Path::new("/tmp/target");
        assert!(safe_join(dir, "skill/docs/x.md").is_ok());
        for bad in ["../outside", "skill/../../outside", "/etc/passwd"] {
            assert!(safe_join(dir, bad).is_err(), "{bad} must be refused");
        }
    }

    /// An engine that ships nothing answers "nothing", rather than failing.
    /// `vibrev install --all` walks every engine it finds, so one skill-less
    /// binary must not be an error.
    #[test]
    fn an_empty_binary_lists_and_exports_nothing() {
        static EMPTY_ARCHIVE: std::sync::LazyLock<Vec<u8>> =
            std::sync::LazyLock::new(|| archive::write(&[]).expect("write"));
        let embedded = Embedded::new(&[], EMPTY_ARCHIVE.as_slice());

        assert!(embedded.all().is_empty());
        assert!(embedded.by_name("anything").is_none());
        assert!(
            embedded
                .export(Path::new("/nonexistent"), None)
                .expect("exporting nothing writes nothing")
                .is_empty()
        );
    }

    #[test]
    fn an_unknown_skill_names_the_ones_that_exist() {
        static ARCHIVE: std::sync::LazyLock<Vec<u8>> =
            std::sync::LazyLock::new(|| archive::write(&[]).expect("write"));
        const ALPHA: &[SkillMeta] = &[SkillMeta {
            name: "alpha",
            description: "a skill",
            files: 1,
            bytes: 1,
            fingerprint: "0000000000000000",
        }];
        let embedded = Embedded::new(ALPHA, ARCHIVE.as_slice());

        let error = embedded
            .export(Path::new("/nonexistent"), Some("nope"))
            .expect_err("must fail");
        assert!(error.to_string().contains("alpha"), "{error}");
    }

    /// A metadata table that disagrees with the archive means the two came
    /// from different builds. Reporting it beats writing a half-exported skill
    /// and calling it done.
    #[test]
    fn a_table_that_disagrees_with_the_archive_is_refused() {
        static ARCHIVE: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
            archive::write(&[("alpha/SKILL.md".to_string(), b"body".to_vec())]).expect("write")
        });
        const CLAIMS_TWO: &[SkillMeta] = &[SkillMeta {
            name: "alpha",
            description: "a skill",
            files: 2,
            bytes: 4,
            fingerprint: "0000000000000000",
        }];
        let embedded = Embedded::new(CLAIMS_TWO, ARCHIVE.as_slice());

        let dir =
            std::env::temp_dir().join(format!("vibrev-skills-mismatch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let error = embedded.export(&dir, None).expect_err("must fail");
        assert!(error.to_string().contains("claims 2"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
