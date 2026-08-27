//! Compile `skills/` into the binary.
//!
//! One line, which is the point: the walking, the frontmatter validation, the
//! fingerprint and the archive are `vibrev-skills`. This engine exists to prove
//! the shared pieces work for a *second* consumer, and the skills path is no
//! different — if this build script needed more than a call, an engine author
//! would still be copying code.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    vibrev_skills::pack::pack(std::path::Path::new(env!("CARGO_MANIFEST_DIR")))
}
