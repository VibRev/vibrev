//! `skills list` and `skills export`, once, for every engine.
//!
//! Served two ways because the engines build their command trees two ways.
//! `ida-headless-mcp` derives its subcommand enum, so it names [`SkillsArgs`]
//! in a variant; `toy-engine` builds with clap's builder API, so it calls
//! [`command`] and [`from_matches`]. Both reach one derived type — the
//! alternative was hand-writing `Args` and `FromArgMatches` over a builder,
//! which is more code than the derive saves and a second place for the two
//! flag sets to disagree.

use std::path::PathBuf;

use crate::{Embedded, Listing};

/// `skills list` / `skills export`.
///
/// Answerable with no database, no license and no analysis backend — this is
/// what an installer calls to ask a binary what knowledge it ships before it
/// decides where to put it.
#[derive(clap::Args, Debug)]
pub struct SkillsArgs {
    #[command(subcommand)]
    command: SkillsCommand,
}

#[derive(clap::Subcommand, Debug)]
enum SkillsCommand {
    /// List the skills this binary carries
    List {
        /// Emit the machine-readable form on stdout
        #[arg(long)]
        json: bool,
    },
    /// Write the skills out, one directory per skill
    Export {
        /// Destination directory; each skill becomes `<DIR>/<name>/`
        #[arg(long, value_name = "DIR")]
        dir: PathBuf,
        /// Export only this skill instead of all of them
        #[arg(long, value_name = "NAME")]
        skill: Option<String>,
        /// Emit the machine-readable form on stdout
        #[arg(long)]
        json: bool,
    },
}

/// The `skills` subcommand, for an engine that builds its tree with the
/// builder API.
pub fn command() -> clap::Command {
    <SkillsArgs as clap::Args>::augment_args(
        clap::Command::new("skills")
            .about("Inspect and export the agent skills built into this binary"),
    )
}

/// Read [`SkillsArgs`] back out of the matches [`command`] produced.
pub fn from_matches(matches: &clap::ArgMatches) -> Result<SkillsArgs, clap::Error> {
    <SkillsArgs as clap::FromArgMatches>::from_arg_matches(matches)
}

impl SkillsArgs {
    /// Run the verb, printing to stdout.
    ///
    /// `server` and `version` are the engine's own — this crate deliberately
    /// does not know either, since `CARGO_PKG_VERSION` expanded here would
    /// report *this* crate's version to an installer asking about the engine.
    pub fn run(
        &self,
        embedded: &Embedded,
        server: &str,
        version: &str,
    ) -> Result<(), anyhow::Error> {
        match &self.command {
            SkillsCommand::List { json } => {
                let skills = embedded.all();
                if *json {
                    println!(
                        "{}",
                        serde_json::to_string(&Listing::new(server, version, skills))?
                    );
                    return Ok(());
                }
                if skills.is_empty() {
                    println!("This build ships no skills.");
                    return Ok(());
                }
                for skill in skills {
                    println!(
                        "{}  {} files  {}  {}",
                        skill.name,
                        skill.files,
                        human_bytes(skill.bytes),
                        skill.fingerprint
                    );
                    println!("  {}", skill.description);
                }
                Ok(())
            }
            SkillsCommand::Export { dir, skill, json } => {
                let exported = embedded.export(dir, skill.as_deref())?;
                if *json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "ok": true,
                            "dir": dir.display().to_string(),
                            "skills": exported.iter().map(|e| serde_json::json!({
                                "name": e.skill.name,
                                "root": e.root.display().to_string(),
                                "files": e.files.len(),
                                "bytes": e.skill.bytes,
                                "fingerprint": e.skill.fingerprint,
                            })).collect::<Vec<_>>(),
                        })
                    );
                    return Ok(());
                }
                for item in &exported {
                    println!(
                        "{}  {} files  {}  -> {}",
                        item.skill.name,
                        item.files.len(),
                        human_bytes(item.skill.bytes),
                        item.root.display()
                    );
                }
                Ok(())
            }
        }
    }
}

fn human_bytes(bytes: usize) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two ways an engine can mount this must accept the same flags. They
    /// go through one derived type precisely so they cannot drift, and this is
    /// the test that says so out loud.
    #[test]
    fn the_builder_form_and_the_derived_form_take_the_same_flags() {
        let matches = command()
            .no_binary_name(true)
            .try_get_matches_from(["export", "--dir", "/tmp/x", "--skill", "alpha", "--json"])
            .expect("the builder form parses every flag");
        let args = from_matches(&matches).expect("and reads back into the derived type");

        let SkillsCommand::Export { dir, skill, json } = args.command else {
            panic!("expected the export verb");
        };
        assert_eq!(dir, PathBuf::from("/tmp/x"));
        assert_eq!(skill.as_deref(), Some("alpha"));
        assert!(json);
    }

    #[test]
    fn list_takes_only_json() {
        let matches = command()
            .no_binary_name(true)
            .try_get_matches_from(["list", "--json"])
            .expect("parse");
        let args = from_matches(&matches).expect("read back");
        assert!(matches!(args.command, SkillsCommand::List { json: true }));

        assert!(
            command()
                .no_binary_name(true)
                .try_get_matches_from(["list", "--dir", "/tmp"])
                .is_err(),
            "list has no --dir"
        );
    }

    /// `--dir` is what the installer passes; forgetting it must be a usage
    /// error, not an export into the current working directory.
    #[test]
    fn export_without_a_destination_is_a_usage_error() {
        assert!(
            command()
                .no_binary_name(true)
                .try_get_matches_from(["export"])
                .is_err()
        );
    }

    #[test]
    fn human_bytes_switches_units_and_keeps_small_sizes_exact() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KB");
        assert_eq!(human_bytes(2 * 1024 * 1024), "2.0 MB");
    }
}
