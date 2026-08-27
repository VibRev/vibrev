//! The shared HTTP bearer token file (`~/.vibrev/token`).
//!
//! Two programs open this file and neither can see the other's source: the
//! installer rotates it, and every engine that opens a listener reads it.
//!
//! # The format, and why it is a list
//!
//! One token per line; blank lines and `#` comments are ignored. **Every** line
//! is accepted, not only the first. That is what makes a rotation safe to
//! interrupt: the new token goes on line one while the outgoing one stays on
//! line two and stays valid, so a client-config rewrite that dies halfway
//! through cannot take a client offline.
//!
//! [`write`] and [`Accepted::accepts`] are the two ends of that promise, and
//! they are in one module for that reason. A rotation whose safety argument
//! lives in one crate and whose enforcement lives in another is an argument
//! nobody can test; here it is one test.
//!
//! # Permissions
//!
//! `O_CREAT|O_EXCL` with mode 0600 at creation, never create-then-chmod: the
//! chmod version leaves a window in which every other user on the host can read
//! the file, and that window is exactly what they need. A file that is *already*
//! loose is reported by [`load_or_create`] rather than quietly used.
//!
//! # What is not here
//!
//! Reading the `Authorization` header and answering `401` needs the `http`
//! crate, so it stays with whichever listener is doing the reading. What crosses
//! that line is [`Accepted`], which is the same question — "is this string one
//! of ours?" — asked without a request in hand.

use std::ffi::OsString;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Prefix on generated tokens. Makes a leaked one greppable and tells a user
/// staring at a config file what they are looking at.
pub const PREFIX: &str = "vbr_";

/// The private directory under the user's home.
pub const DIR_NAME: &str = ".vibrev";

/// The token file inside it.
pub const FILE_NAME: &str = "token";

/// Environment override for [`dir`]. Every program that touches the token file
/// has to honour it, so that setting it moves *all* of them together: a reader
/// that ignores it while `vibrev token rotate` obeys it rotates one file while
/// the server reads another, and every client gets a 401 out of a
/// correctly-executed rotation.
pub const DIR_ENV: &str = "VIBREV_HOME";

const HEADER: &str = "\
# vibrev shared HTTP bearer token.\n\
# One token per line; blank lines and #-comments are ignored.\n\
# The first entry is the current token. During a rotation the previous\n\
# token stays on a later line and stays accepted, so a rotation that\n\
# fails halfway through does not take any client offline.\n";

/// How many times to retry the read/create cycle before giving up.
///
/// One retry covers the documented race (`install` and `serve` both deciding to
/// generate); the extra rounds only cover a file being deleted between our
/// create and our read.
const CREATE_RETRIES: usize = 3;

#[derive(Debug)]
pub enum TokenError {
    Empty {
        path: PathBuf,
    },
    Read {
        path: PathBuf,
        source: io::Error,
    },
    Create {
        path: PathBuf,
        source: io::Error,
    },
    CreateDir {
        path: PathBuf,
        source: io::Error,
    },
    Write {
        path: PathBuf,
        source: io::Error,
    },
    /// Neither [`DIR_ENV`] nor a home directory. The caller has to be told to
    /// name the file, because there is nowhere to guess it.
    NoHome,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::Empty { path } => write!(
                f,
                "token file {} is empty; it must hold at least one token, one per line",
                path.display()
            ),
            TokenError::Read { path, source } => {
                write!(f, "failed to read token file {}: {source}", path.display())
            }
            TokenError::Create { path, source } => {
                write!(
                    f,
                    "failed to create token file {}: {source}",
                    path.display()
                )
            }
            TokenError::CreateDir { path, source } => write!(
                f,
                "failed to create token directory {}: {source}",
                path.display()
            ),
            TokenError::Write { path, source } => {
                write!(f, "failed to write token file {}: {source}", path.display())
            }
            TokenError::NoHome => write!(
                f,
                "cannot locate the home directory for ~/{DIR_NAME}/{FILE_NAME}; \
                 set {DIR_ENV} or name the file explicitly"
            ),
        }
    }
}

impl std::error::Error for TokenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TokenError::Read { source, .. }
            | TokenError::Create { source, .. }
            | TokenError::CreateDir { source, .. }
            | TokenError::Write { source, .. } => Some(source),
            TokenError::Empty { .. } | TokenError::NoHome => None,
        }
    }
}

/// The private directory: [`DIR_ENV`] if set, else `home/.vibrev`.
///
/// `home` is the caller's own answer to "where is the user's home directory",
/// because the two callers disagree about how to find it and this module has no
/// business settling that. What it does settle is the part they must agree on:
/// that the override wins, and that the directory is called `.vibrev`.
pub fn dir(home: Option<&Path>) -> Option<PathBuf> {
    resolve_dir(std::env::var_os(DIR_ENV), home)
}

fn resolve_dir(override_dir: Option<OsString>, home: Option<&Path>) -> Option<PathBuf> {
    match override_dir.filter(|value| !value.is_empty()) {
        Some(explicit) => Some(PathBuf::from(explicit)),
        None => home.map(|home| home.join(DIR_NAME)),
    }
}

/// The token file inside an already-resolved directory.
pub fn path_in(dir: &Path) -> PathBuf {
    dir.join(FILE_NAME)
}

/// `$VIBREV_HOME/token`, else `$HOME/.vibrev/token`.
///
/// For a consumer that has no notion of a home directory of its own. The
/// installer resolves its root once for `config.toml` and `engines/` too, and
/// calls [`dir`] plus [`path_in`] instead.
pub fn default_path() -> Result<PathBuf, TokenError> {
    dir(home_dir().as_deref())
        .map(|dir| path_in(&dir))
        .ok_or(TokenError::NoHome)
}

fn home_dir() -> Option<PathBuf> {
    let home = if cfg!(windows) {
        std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"))
    } else {
        std::env::var_os("HOME")
    };
    home.map(PathBuf::from)
}

/// What [`load_or_create`] did, for a startup banner to report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The file already existed and was read.
    Existing,
    /// This process created the file and wrote a fresh token into it.
    Generated,
}

/// Something worth telling the operator that is not a reason to refuse to start.
///
/// A variant rather than a rendered string because the two consumers say
/// different things about the same fact: an engine that just opened the file
/// tells you to `chmod` it, while the installer — which is about to rewrite it
/// at 0600 anyway — has to say the harder thing, that the token it is rotating
/// away from should be assumed leaked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning {
    /// The file's permission bits let somebody other than the owner read it.
    WorldReadable { path: PathBuf, mode: u32 },
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Warning::WorldReadable { path, mode } => write!(
                f,
                "token file {} is mode {mode:04o}; other users on this host can read it. \
                 Fix with: chmod 600 {}",
                path.display(),
                path.display()
            ),
        }
    }
}

/// Deliberately not `Debug`: it holds the credentials. [`Accepted`] is the type
/// that can be printed.
pub struct Loaded {
    pub tokens: Vec<String>,
    pub origin: Origin,
    /// Non-fatal problems worth telling the operator about.
    pub warnings: Vec<Warning>,
}

/// Read the token file, generating it on first use.
///
/// Generation is `O_CREAT|O_EXCL`: losing that race means somebody else just
/// created the file, so re-read rather than generating a second token. A second
/// token would win the write and silently invalidate whatever the first
/// generator already wrote into a client config.
pub fn load_or_create(path: &Path) -> Result<Loaded, TokenError> {
    for attempt in 0..CREATE_RETRIES {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                let tokens = parse(&contents);
                if tokens.is_empty() {
                    return Err(TokenError::Empty {
                        path: path.to_path_buf(),
                    });
                }
                return Ok(Loaded {
                    tokens,
                    origin: Origin::Existing,
                    warnings: permission_warnings(path),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(TokenError::Read {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }

        match create(path) {
            Ok(token) => {
                return Ok(Loaded {
                    tokens: vec![token],
                    origin: Origin::Generated,
                    warnings: Vec::new(),
                });
            }
            // Somebody created it between our read and our create. Their token
            // is the one that counts; go back and read it.
            Err(TokenError::Create { source, .. })
                if source.kind() == io::ErrorKind::AlreadyExists
                    && attempt + 1 < CREATE_RETRIES => {}
            Err(error) => return Err(error),
        }
    }

    Err(TokenError::Read {
        path: path.to_path_buf(),
        source: io::Error::other("token file kept disappearing between read and create"),
    })
}

/// Replace the file with exactly `tokens`, in order, current one first.
///
/// The rewrite goes through a sibling in the same private directory and a
/// rename, so a reader arriving mid-write sees the old list or the new one and
/// never a truncated file — a listener that read half a token file would reject
/// every client until the next restart.
///
/// Comments the user added at the top are kept. The file is documentation as
/// much as it is data, and a rotation is not an invitation to throw away what
/// somebody wrote in it.
pub fn write(path: &Path, tokens: &[String]) -> Result<(), TokenError> {
    let existing = std::fs::read_to_string(path).ok();
    replace(path, &render(existing.as_deref(), tokens))
}

fn render(existing: Option<&str>, tokens: &[String]) -> String {
    let mut body = existing
        .map(leading_comments)
        .filter(|comments| !comments.trim().is_empty())
        .unwrap_or_else(|| HEADER.to_owned());
    if !body.ends_with('\n') {
        body.push('\n');
    }
    for token in tokens {
        body.push_str(token);
        body.push('\n');
    }
    body
}

fn leading_comments(contents: &str) -> String {
    contents
        .lines()
        .take_while(|line| {
            let trimmed = line.trim();
            trimmed.is_empty() || trimmed.starts_with('#')
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Tokens in file order. The first is the current one; the rest are accepted
/// only so an in-progress rotation cannot strand a client.
pub fn parse(contents: &str) -> Vec<String> {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// 244 bits from the OS CSPRNG, hex-encoded behind [`PREFIX`].
///
/// Two v4 UUIDs rather than one so the value is not mistaken for a UUID that
/// something else might feel free to regenerate, and so the entropy has room to
/// spare over the 128-bit floor.
pub fn generate() -> String {
    let high = uuid::Uuid::new_v4().simple();
    let low = uuid::Uuid::new_v4().simple();
    format!("{PREFIX}{high}{low}")
}

/// A fresh token that is not already in `existing`.
///
/// The collision it guards against will not happen; the point is that a
/// rotation which *did* collide would report a new token while leaving the old
/// one live, and no test would ever catch it.
pub fn generate_distinct(existing: &[String]) -> String {
    loop {
        let token = generate();
        if !existing.iter().any(|taken| taken == &token) {
            return token;
        }
    }
}

fn create(path: &Path) -> Result<String, TokenError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        create_dir(parent)?;
    }
    let token = generate();
    create_private(path, &format!("{HEADER}{token}\n")).map_err(|source| TokenError::Create {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(token)
}

fn replace(path: &Path, body: &str) -> Result<(), TokenError> {
    let dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    create_dir(dir)?;

    // A sibling, so the rename stays within one filesystem and the staged file
    // is never more readable than the file it is about to become.
    let staged = dir.join(format!(".{FILE_NAME}.{}", uuid::Uuid::new_v4().simple()));
    if let Err(source) = create_private(&staged, body) {
        std::fs::remove_file(&staged).ok();
        return Err(TokenError::Write {
            path: staged,
            source,
        });
    }
    if let Err(source) = std::fs::rename(&staged, path) {
        std::fs::remove_file(&staged).ok();
        return Err(TokenError::Write {
            path: path.to_path_buf(),
            source,
        });
    }
    Ok(())
}

/// Create `path` at mode 0600 and write `body`. Fails if it already exists.
fn create_private(path: &Path, body: &str) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(body.as_bytes())?;
    file.sync_all()
}

fn create_dir(path: &Path) -> Result<(), TokenError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(source) => Err(TokenError::CreateDir {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(unix)]
fn permission_warnings(path: &Path) -> Vec<Warning> {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = std::fs::metadata(path) else {
        return Vec::new();
    };
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 == 0 {
        return Vec::new();
    }
    vec![Warning::WorldReadable {
        path: path.to_path_buf(),
        mode,
    }]
}

#[cfg(not(unix))]
fn permission_warnings(_path: &Path) -> Vec<Warning> {
    Vec::new()
}

/// The token set one listener accepts.
///
/// There is deliberately no constructor for "no tokens": an empty set would be
/// an unauthenticated listener wearing an authenticated type.
#[derive(Clone)]
pub struct Accepted {
    inner: Arc<Inner>,
}

struct Inner {
    accepted: Vec<String>,
    source: Option<PathBuf>,
}

/// Hand-written so a stray `{:?}` cannot print the credential. This is not
/// hypothetical: the listener carries it inside a policy struct that derives
/// `Debug` and is threaded through the HTTP framework's state.
impl fmt::Debug for Accepted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accepted")
            .field("accepted", &self.inner.accepted.len())
            .field("source", &self.inner.source)
            .finish()
    }
}

impl Accepted {
    pub fn new(tokens: Vec<String>, source: Option<PathBuf>) -> Result<Self, TokenError> {
        if tokens.is_empty() {
            return Err(TokenError::Empty {
                path: source.unwrap_or_else(|| PathBuf::from("<memory>")),
            });
        }
        Ok(Self {
            inner: Arc::new(Inner {
                accepted: tokens,
                source,
            }),
        })
    }

    /// [`load_or_create`] plus [`Accepted::new`]; the [`Loaded`] comes back so a
    /// caller can still report the origin and the warnings.
    pub fn load(path: &Path) -> Result<(Self, Loaded), TokenError> {
        let loaded = load_or_create(path)?;
        let accepted = Self::new(loaded.tokens.clone(), Some(path.to_path_buf()))?;
        Ok((accepted, loaded))
    }

    /// The current token — the first line of the file. This is the one a client
    /// config should carry.
    pub fn primary(&self) -> &str {
        &self.inner.accepted[0]
    }

    pub fn count(&self) -> usize {
        self.inner.accepted.len()
    }

    pub fn source(&self) -> Option<&Path> {
        self.inner.source.as_deref()
    }

    /// Check one candidate against every accepted token.
    ///
    /// Deliberately not `==`, and deliberately not `any()`: both stop at the
    /// first mismatch, and the time that takes is a function of how many leading
    /// bytes the guess got right. That turns a 244-bit secret into 64
    /// independent one-byte guesses. `fold` visits every entry and
    /// [`constant_time_eq`] visits every byte.
    pub fn accepts(&self, candidate: &str) -> bool {
        self.inner.accepted.iter().fold(false, |matched, accepted| {
            matched | constant_time_eq(accepted.as_bytes(), candidate.as_bytes())
        })
    }
}

/// Compare without leaking, through timing, how much of `expected` a guess got
/// right.
///
/// The loop runs over `expected`, so its trip count depends only on the stored
/// token's length — a fixed, public property of the format, not a secret. A
/// shorter guess is indexed modulo its own length rather than being allowed to
/// end the loop early; the length mismatch is folded into the accumulator so it
/// still fails. `black_box` keeps an optimizer from noticing that the
/// accumulator can never return to zero and reinstating the early exit we just
/// removed.
fn constant_time_eq(expected: &[u8], candidate: &[u8]) -> bool {
    if candidate.is_empty() {
        return expected.is_empty();
    }
    let mut diff = (expected.len() ^ candidate.len()) as u32;
    for (index, byte) in expected.iter().enumerate() {
        let other = candidate[index % candidate.len()];
        diff = std::hint::black_box(diff | u32::from(byte ^ other));
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        // Not a shared fixture directory: these tests run in parallel with every
        // other test in the crate and one of them chmods a file.
        let dir = std::env::temp_dir().join(format!(
            "vibrev-kit-token-{tag}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn accepted(tokens: &[&str]) -> Accepted {
        Accepted::new(tokens.iter().map(|t| (*t).to_owned()).collect(), None)
            .expect("non-empty token set")
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    /// The invariant the installer's rotation rests on, stated once where both
    /// halves of it are visible: whatever [`parse`] hands back, [`Accepted`]
    /// takes. If these two ever disagree about which lines count, a rotation
    /// that has written the new token but not yet rewritten a client config
    /// logs the old one out — the exact failure the list format exists to
    /// prevent, and one that no test on either side alone would see.
    #[test]
    fn every_line_the_parser_returns_is_a_line_the_listener_accepts() {
        let file = format!(
            "# a comment\n\n  {PREFIX}current  \n{PREFIX}previous\n# trailing\n\n{PREFIX}older\n"
        );
        let tokens = parse(&file);
        assert_eq!(
            tokens,
            [
                format!("{PREFIX}current"),
                format!("{PREFIX}previous"),
                format!("{PREFIX}older"),
            ]
        );

        let accepted = Accepted::new(tokens.clone(), None).expect("non-empty");
        for token in &tokens {
            assert!(accepted.accepts(token), "{token} was written but not taken");
        }
        assert_eq!(accepted.primary(), format!("{PREFIX}current"));
        assert!(!accepted.accepts("# a comment"));
        assert!(!accepted.accepts(""));
    }

    #[test]
    fn a_generated_file_is_owner_only_and_reused() {
        let dir = scratch("generate");
        let path = dir.join("nested").join(FILE_NAME);

        let first = load_or_create(&path).expect("generate");
        assert_eq!(first.origin, Origin::Generated);
        assert_eq!(first.tokens.len(), 1);
        assert!(first.tokens[0].starts_with(PREFIX));
        assert!(first.warnings.is_empty());

        #[cfg(unix)]
        {
            assert_eq!(
                mode_of(&path),
                0o600,
                "the file must be 0600 the moment it exists"
            );
            assert_eq!(mode_of(path.parent().expect("parent")), 0o700);
        }

        // A restart must not invalidate every installed client config.
        let second = load_or_create(&path).expect("reuse");
        assert_eq!(second.origin, Origin::Existing);
        assert_eq!(second.tokens, first.tokens);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_existing_file_is_never_overwritten_by_generation() {
        let dir = scratch("exclusive");
        let path = path_in(&dir);
        std::fs::write(&path, "vbr_preexisting\n").expect("seed");

        let loaded = load_or_create(&path).expect("read");
        assert_eq!(loaded.origin, Origin::Existing);
        assert_eq!(loaded.tokens, ["vbr_preexisting"]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_empty_token_file_is_an_error_not_an_open_door() {
        let dir = scratch("empty");
        let path = path_in(&dir);
        std::fs::write(&path, "# only a comment\n\n").expect("seed");

        assert!(matches!(
            load_or_create(&path),
            Err(TokenError::Empty { .. })
        ));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_group_readable_token_file_is_reported() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch("perms");
        let path = path_in(&dir);
        std::fs::write(&path, "vbr_loose\n").expect("seed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        let loaded = load_or_create(&path).expect("read");
        assert_eq!(
            loaded.warnings,
            [Warning::WorldReadable {
                path: path.clone(),
                mode: 0o644
            }]
        );
        assert!(
            loaded.warnings[0]
                .to_string()
                .contains("other users on this host can read it")
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_rewrite_keeps_the_comments_and_the_mode() {
        let dir = scratch("rewrite");
        let path = path_in(&dir);
        write(&path, &["vbr_first".to_owned()]).expect("first write");
        std::fs::write(
            &path,
            format!(
                "# a note the operator added\n{}",
                std::fs::read_to_string(&path).expect("read back")
            ),
        )
        .expect("annotate");

        write(&path, &["vbr_second".to_owned(), "vbr_first".to_owned()]).expect("rotate");

        let contents = std::fs::read_to_string(&path).expect("read");
        assert!(
            contents.contains("# a note the operator added"),
            "{contents}"
        );
        assert_eq!(parse(&contents), ["vbr_second", "vbr_first"]);
        #[cfg(unix)]
        assert_eq!(mode_of(&path), 0o600);

        // The staging sibling is not left behind for the next operator to find.
        let strays: Vec<_> = std::fs::read_dir(&dir)
            .expect("list")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .filter(|name| name != FILE_NAME)
            .collect();
        assert!(strays.is_empty(), "{strays:?}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_rewrite_of_a_file_that_is_not_there_yet_writes_the_header() {
        let dir = scratch("rewrite-fresh");
        let path = dir.join("nested").join(FILE_NAME);

        write(&path, &["vbr_only".to_owned()]).expect("write");

        let contents = std::fs::read_to_string(&path).expect("read");
        assert!(
            contents.starts_with("# vibrev shared HTTP bearer token"),
            "{contents}"
        );
        assert_eq!(parse(&contents), ["vbr_only"]);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The two ways a token file comes into existence must produce the same
    /// header, or the file a user reads depends on which program got there
    /// first.
    #[test]
    fn creation_and_rewrite_write_the_same_preamble() {
        let generated = scratch("preamble-generated");
        let written = scratch("preamble-written");
        let by_engine = path_in(&generated);
        let by_installer = path_in(&written);

        let loaded = load_or_create(&by_engine).expect("generate");
        write(&by_installer, &loaded.tokens).expect("write");

        assert_eq!(
            std::fs::read_to_string(&by_engine).expect("read"),
            std::fs::read_to_string(&by_installer).expect("read"),
        );

        std::fs::remove_dir_all(&generated).ok();
        std::fs::remove_dir_all(&written).ok();
    }

    #[test]
    fn the_override_wins_and_an_empty_one_does_not() {
        let home = Path::new("/home/tester");
        assert_eq!(
            resolve_dir(Some(OsString::from("/srv/vibrev")), Some(home)),
            Some(PathBuf::from("/srv/vibrev"))
        );
        assert_eq!(
            resolve_dir(None, Some(home)),
            Some(home.join(DIR_NAME)),
            "without the override it is ~/{DIR_NAME}"
        );
        // An exported-but-empty variable is a shell accident, not a location.
        assert_eq!(
            resolve_dir(Some(OsString::new()), Some(home)),
            Some(home.join(DIR_NAME))
        );
        assert_eq!(resolve_dir(None, None), None);
    }

    #[test]
    fn a_fresh_token_is_never_one_already_in_the_file() {
        let existing = vec![format!("{PREFIX}taken")];
        let token = generate_distinct(&existing);
        assert!(token.starts_with(PREFIX));
        assert!(!existing.contains(&token));
        assert_ne!(generate(), generate());
    }

    #[test]
    fn every_listed_token_is_accepted_so_a_rotation_can_be_half_done() {
        let accepted = accepted(&["vbr_new", "vbr_old"]);
        assert!(accepted.accepts("vbr_new"));
        assert!(accepted.accepts("vbr_old"));
        assert!(!accepted.accepts("vbr_other"));
        assert_eq!(accepted.primary(), "vbr_new");
        assert_eq!(accepted.count(), 2);
    }

    #[test]
    fn an_empty_token_set_cannot_be_constructed() {
        assert!(matches!(
            Accepted::new(Vec::new(), None),
            Err(TokenError::Empty { .. })
        ));
    }

    #[test]
    fn debug_never_prints_the_token() {
        let rendered = format!("{:?}", accepted(&["vbr_supersecret"]));
        assert!(!rendered.contains("vbr_supersecret"), "{rendered}");
        assert!(rendered.contains('1'), "the count is still useful");
    }

    #[test]
    fn constant_time_eq_still_decides_correctly() {
        assert!(constant_time_eq(b"abcd", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abce"));
        // A prefix must not pass just because the loop indexes modulo.
        assert!(!constant_time_eq(b"abcd", b"ab"));
        assert!(!constant_time_eq(b"abcd", b"abcdabcd"));
        assert!(!constant_time_eq(b"abcd", b""));
        assert!(constant_time_eq(b"", b""));
    }
}
