//! The blob format, both directions.
//!
//! Writer and reader live in one file on purpose. They are two halves of one
//! agreement, and the failure they can have — a build script that writes what
//! the binary cannot read — is silent until someone runs `skills export` on a
//! shipped binary. Splitting them across a build crate and a runtime crate is
//! exactly how that agreement drifts.
//!
//! A flat sequence of `(path, body)` chunks: `u32` count, then `u32` length +
//! bytes per field, sorted by path. There is no notion of a *skill* in here —
//! grouping happens at unpack time on the leading path component, which is why
//! adding a skill changes no format.
//!
//! Deliberately not tar: uid/gid/mode mean nothing for text documents, and
//! tar's mtime would make the build unreproducible for no gain. Zlib rather
//! than gzip for the same reason — the gzip header carries a timestamp.

use std::io::{Read, Write};

/// Serialize `(path, body)` pairs, then compress.
pub(crate) fn write(entries: &[(String, Vec<u8>)]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut raw = Vec::new();
    let count: u32 = entries.len().try_into()?;
    raw.extend_from_slice(&count.to_le_bytes());
    for (path, body) in entries {
        push_chunk(&mut raw, path.as_bytes())?;
        push_chunk(&mut raw, body)?;
    }

    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(&raw)?;
    Ok(encoder.finish()?)
}

fn push_chunk(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let len: u32 = bytes.len().try_into()?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Decompress and parse back into `(path, contents)` pairs.
pub(crate) fn read(archive: &[u8]) -> Result<Vec<(String, Vec<u8>)>, ArchiveError> {
    let mut raw = Vec::new();
    flate2::read::ZlibDecoder::new(archive)
        .read_to_end(&mut raw)
        .map_err(|_| ArchiveError("the embedded skill archive is corrupt"))?;

    let mut reader = Reader { buf: &raw, pos: 0 };
    let count = reader.u32()?;
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let path = std::str::from_utf8(reader.chunk()?)
            .map_err(|_| ArchiveError("a skill path in the archive is not UTF-8"))?
            .to_owned();
        out.push((path, reader.chunk()?.to_vec()));
    }
    Ok(out)
}

/// The archive did not parse. Carries a fixed reason rather than a position:
/// every case means the same thing to a caller — this binary's own build
/// output is not what this code expects — and no user action depends on which.
#[derive(Debug)]
pub struct ArchiveError(&'static str);

impl std::fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for ArchiveError {}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn u32(&mut self) -> Result<u32, ArchiveError> {
        let end = self.pos + 4;
        let bytes: [u8; 4] = self
            .buf
            .get(self.pos..end)
            .and_then(|s| s.try_into().ok())
            .ok_or(ArchiveError("the embedded skill archive ends mid-header"))?;
        self.pos = end;
        Ok(u32::from_le_bytes(bytes))
    }

    fn chunk(&mut self) -> Result<&'a [u8], ArchiveError> {
        let len = self.u32()? as usize;
        let end = self.pos + len;
        let bytes = self
            .buf
            .get(self.pos..end)
            .ok_or(ArchiveError("the embedded skill archive ends mid-chunk"))?;
        self.pos = end;
        Ok(bytes)
    }
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;

/// FNV-1a over the sorted `(path, contents)` sequence.
///
/// Answers one question: is the copy on disk the one this binary carries. That
/// is a staleness check, so a non-cryptographic hash is the right size of tool
/// — someone who can write into a skill directory has already won by other
/// means. Inline rather than pulled in, because a build script that adds a hash
/// crate to produce sixteen hex digits pays a lot for very little.
pub(crate) fn fingerprint(entries: &[(String, Vec<u8>)]) -> u64 {
    let mut hash = FNV_OFFSET;
    for (path, body) in entries {
        hash = fnv1a(path.as_bytes(), hash);
        hash = fnv1a(body, hash);
    }
    hash
}

fn fnv1a(bytes: &[u8], seed: u64) -> u64 {
    let mut hash = seed;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<(String, Vec<u8>)> {
        vec![
            ("a/SKILL.md".to_string(), b"---\nname: a\n---\n".to_vec()),
            ("a/docs/one.md".to_string(), b"body".to_vec()),
            ("b/SKILL.md".to_string(), Vec::new()),
        ]
    }

    #[test]
    fn the_writer_and_the_reader_agree() {
        let packed = write(&entries()).expect("write");
        assert_eq!(read(&packed).expect("read"), entries());
    }

    /// An empty archive is the shape a build with no `skills/` directory
    /// produces, and it has to parse — otherwise every engine that ships no
    /// skills fails at `skills list` instead of printing nothing.
    #[test]
    fn an_empty_archive_round_trips() {
        let packed = write(&[]).expect("write");
        assert!(read(&packed).expect("read").is_empty());
    }

    #[test]
    fn a_truncated_archive_is_an_error_not_a_panic() {
        let packed = write(&entries()).expect("write");
        // Truncating the *compressed* bytes fails in the decoder; truncating
        // after a valid decompress is what the Reader bounds checks are for.
        assert!(read(&packed[..packed.len() / 2]).is_err());
        assert!(read(b"not zlib at all").is_err());
    }

    #[test]
    fn the_fingerprint_follows_content_and_order() {
        let base = fingerprint(&entries());
        assert_eq!(base, fingerprint(&entries()), "must be deterministic");

        let mut renamed = entries();
        renamed[1].0 = "a/docs/two.md".to_string();
        assert_ne!(base, fingerprint(&renamed), "a path is part of the skill");

        let mut edited = entries();
        edited[1].1 = b"other".to_vec();
        assert_ne!(base, fingerprint(&edited));

        let mut reordered = entries();
        reordered.swap(0, 2);
        assert_ne!(
            base,
            fingerprint(&reordered),
            "order matters, which is why the packer sorts"
        );
    }
}
