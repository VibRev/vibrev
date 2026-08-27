//! Scratch directories for tests.
//!
//! Deliberately *not* `std::env::temp_dir()`: `/tmp` is a small tmpfs on the
//! development machines and these tests write whole fake home directories. Using
//! a path next to the test binary puts them inside `target/`, where `cargo clean`
//! already knows to remove them.

use camino::Utf8PathBuf;
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

/// A clean, empty directory unique to `tag`. Wiped on entry, so a test always
/// starts from nothing even if a previous run panicked halfway through.
///
/// # Tags must be unique within a test binary
///
/// The wipe is what makes a reused tag dangerous. cargo runs a binary's tests on
/// several threads, so two tests sharing a tag do not merely share a directory:
/// whichever calls `scratch` second deletes the tree the first one is in the
/// middle of using. `install::tests::a_directory_we_did_not_write_is_never_touched`
/// and `skill::tests::a_directory_without_our_marker_is_foreign` both used
/// `"skill-foreign"`, and the result was a test that failed roughly one run in
/// twenty-five with `Added` where `Foreign` was expected — the directory it had
/// just created was gone by the time the planner looked.
///
/// So a repeated tag panics here, on the second call, naming both the tag and
/// what to do about it. A collision is a mistake either way; the only question
/// is whether it surfaces as this message or as an intermittent failure
/// somewhere else entirely.
pub fn scratch(tag: &str) -> Utf8PathBuf {
    static CLAIMED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let fresh = CLAIMED
        .get_or_init(Mutex::default)
        .lock()
        .expect("scratch tag registry")
        .insert(tag.to_owned());
    assert!(
        fresh,
        "scratch tag {tag:?} is used by more than one test in this binary; \
         `scratch` wipes the directory on entry, so the two would delete each \
         other's files at random. Give one of them a different tag."
    );

    let exe = std::env::current_exe().expect("test binary has a path");
    let base = Utf8PathBuf::from_path_buf(exe.parent().expect("…in a directory").to_owned())
        .expect("cargo target dir is UTF-8")
        .join("vibrev-test-scratch")
        .join(tag);
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("scratch dir is creatable");
    base
}

#[cfg(test)]
mod tests {
    use super::scratch;

    #[test]
    #[should_panic(expected = "used by more than one test")]
    fn a_reused_tag_is_refused_rather_than_left_to_race() {
        let first = scratch("testutil-guard");
        assert!(first.exists());
        let _second = scratch("testutil-guard");
    }
}
