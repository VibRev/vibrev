//! The document `skills list --json` prints and `vibrev` reads.
//!
//! One type, both ends.
//!
//! Every field the installer reads is `#[serde(default)]` on purpose. The
//! installer runs a binary it merely found on disk, which may be older than the
//! document it is being asked to produce; missing means absent, not malformed.
//! An engine that answers with `{}` reports "no skills", which is exactly what
//! `vibrev install --all` should do with a stale engine.

use serde::{Deserialize, Serialize};

use crate::SkillMeta;

/// One skill as an engine describes it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Skill {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub files: usize,
    #[serde(default)]
    pub bytes: usize,
    /// Opaque to the installer: the only operation is equality against what is
    /// recorded on disk, which is what makes "already up to date" cheap.
    #[serde(default)]
    pub fingerprint: String,
}

impl From<&SkillMeta> for Skill {
    fn from(meta: &SkillMeta) -> Self {
        Self {
            name: meta.name.to_owned(),
            description: meta.description.to_owned(),
            files: meta.files,
            bytes: meta.bytes,
            fingerprint: meta.fingerprint.to_owned(),
        }
    }
}

/// `<engine> skills list --json`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Listing {
    pub ok: bool,
    /// The name the engine calls itself. Not an engine *id*: an engine does not
    /// know what an installer's registry calls it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(default)]
    pub skills: Vec<Skill>,
}

impl Listing {
    pub fn new(server: &str, version: &str, skills: &[SkillMeta]) -> Self {
        Self {
            ok: true,
            server: server.to_owned(),
            version: version.to_owned(),
            skills: skills.iter().map(Skill::from).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALPHA: &[SkillMeta] = &[SkillMeta {
        name: "alpha",
        description: "does a thing",
        files: 3,
        bytes: 99,
        fingerprint: "0123456789abcdef",
    }];

    /// The wire names are the contract. A rename here is a silent break of an
    /// installer that is already on someone's machine, so the test spells them
    /// out rather than round-tripping the type against itself.
    #[test]
    fn the_document_has_the_field_names_the_installer_reads() {
        let value =
            serde_json::to_value(Listing::new("toy-engine", "0.0.1", ALPHA)).expect("serialize");
        assert_eq!(value["ok"], true);
        assert_eq!(value["server"], "toy-engine");
        assert_eq!(value["version"], "0.0.1");
        assert_eq!(value["skills"][0]["name"], "alpha");
        assert_eq!(value["skills"][0]["description"], "does a thing");
        assert_eq!(value["skills"][0]["files"], 3);
        assert_eq!(value["skills"][0]["bytes"], 99);
        assert_eq!(value["skills"][0]["fingerprint"], "0123456789abcdef");
    }

    /// An engine older than a field must not make the installer fail — it
    /// reports "ships no skills" and `vibrev install --all` carries on.
    #[test]
    fn a_sparse_document_from_an_older_engine_still_parses() {
        let listing: Listing = serde_json::from_str(r#"{"ok":true}"#).expect("parse");
        assert!(listing.skills.is_empty());
        assert_eq!(listing.server, "");

        let listing: Listing =
            serde_json::from_str(r#"{"ok":true,"skills":[{"name":"alpha"}]}"#).expect("parse");
        assert_eq!(listing.skills[0].name, "alpha");
        assert_eq!(listing.skills[0].fingerprint, "");
    }

    #[test]
    fn the_document_round_trips() {
        let listing = Listing::new("toy-engine", "0.0.1", ALPHA);
        let text = serde_json::to_string(&listing).expect("serialize");
        assert_eq!(
            serde_json::from_str::<Listing>(&text).expect("parse"),
            listing
        );
    }
}
