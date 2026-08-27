//! The skills handshake, against a real binary, through the installer's type.
//!
//! `vibrev-skills` unit tests cover packing, unpacking and the document shape as
//! functions. What they cannot cover is the part that only exists once a build
//! script has run and a process is on disk: that `build.rs` walked the right
//! directory, that `include!` bound the table to the archive, that the JSON on
//! stdout parses as [`vibrev_skills::Listing`] — the very type
//! `vibrev::skill::offered` parses it with — and that what lands on disk is the
//! repository byte for byte.
//!
//! That last one is the claim that matters. `vibrev install` writes into
//! `~/.claude/skills`, and the only reason a user should trust it is that what
//! arrives is what was committed.

use std::path::{Path, PathBuf};
use std::process::Command;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("toy-skills-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

/// Run the engine from a directory that is not the repository.
///
/// An installer runs a binary it found on `PATH` from wherever it happens to
/// be. A skills path that resolved anything relative to the current directory
/// would pass every in-repo test and fail on a user's machine.
fn engine(args: &[&str], cwd: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_toy-engine"))
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn toy-engine")
}

fn source_skills() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("skills")
}

#[test]
fn the_listing_parses_as_the_type_the_installer_reads() {
    let root = scratch("list");
    let out = engine(&["skills", "list", "--json"], &root);
    assert!(out.status.success(), "skills list --json must succeed");

    let listing: vibrev_skills::Listing =
        serde_json::from_slice(&out.stdout).expect("the document the installer parses");
    assert!(listing.ok);
    assert_eq!(listing.server, "toy-engine");
    assert!(!listing.version.is_empty());

    let skill = listing
        .skills
        .iter()
        .find(|s| s.name == "toy-reference")
        .expect("this engine ships toy-reference");
    assert_eq!(skill.files, 2);
    assert!(skill.bytes > 0);
    assert_eq!(
        skill.fingerprint.len(),
        16,
        "the installer compares this against a marker file"
    );
    assert!(!skill.description.is_empty());
}

#[test]
fn an_export_reproduces_the_repository_byte_for_byte() {
    let root = scratch("export");
    let into = root.join("into");
    std::fs::create_dir_all(&into).expect("dest");

    let out = engine(
        &["skills", "export", "--dir", into.to_str().expect("utf-8")],
        &root,
    );
    assert!(
        out.status.success(),
        "export failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let source = source_skills();
    let mut checked = 0;
    for entry in walk(&into.join("toy-reference")) {
        let rel = entry.strip_prefix(&into).expect("under the destination");
        assert_eq!(
            std::fs::read(&entry).expect("exported file"),
            std::fs::read(source.join(rel)).expect("source file"),
            "{} differs from the repository copy",
            rel.display()
        );
        checked += 1;
    }
    assert_eq!(checked, 2, "both files of the skill were written");

    let _ = std::fs::remove_dir_all(&root);
}

/// The two things an installer does when it wants one skill and when it asks
/// for one that is not there. The second must fail loudly: `offered` already
/// swallows every *silent* way an engine can decline, so a typo that exported
/// nothing and exited zero would be indistinguishable from success.
#[test]
fn a_named_skill_is_exported_alone_and_an_unknown_one_fails() {
    let root = scratch("named");
    let into = root.join("into");
    std::fs::create_dir_all(&into).expect("dest");

    let out = engine(
        &[
            "skills",
            "export",
            "--dir",
            into.to_str().expect("utf-8"),
            "--skill",
            "toy-reference",
        ],
        &root,
    );
    assert!(out.status.success());
    assert!(into.join("toy-reference/SKILL.md").is_file());

    let out = engine(
        &[
            "skills",
            "export",
            "--dir",
            into.to_str().expect("utf-8"),
            "--skill",
            "nope",
        ],
        &root,
    );
    assert!(!out.status.success(), "an unknown skill must exit non-zero");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("toy-reference"),
        "the error should name what does exist: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// The engine answers with no MCP session, no server, and nothing initialized.
/// An installer inspects a binary before it decides anything, so needing a
/// running server here would make the command useless where it is used.
#[test]
fn listing_needs_no_server_and_no_working_directory() {
    let root = scratch("standalone");
    let out = engine(&["skills", "list"], &root);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("toy-reference"), "{text}");
    let _ = std::fs::remove_dir_all(&root);
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out.sort();
    out
}
