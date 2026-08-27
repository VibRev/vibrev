//! One page of a longer answer, and the truth about what is left behind it.
//!
//! A paged tool answers a question it was not asked. The client asked "what are
//! the imports"; the tool answers "here are a hundred imports", and the
//! difference between *those hundred* and *the hundred that exist* is not in the
//! payload unless the tool puts it there. A list of a hundred names is a
//! believable answer either way, which is what makes the omission expensive: a
//! caller cannot detect it, so it does not read as an error, it reads as a
//! smaller database.
//!
//! Two engines each wrote that arithmetic once per tool — twenty-three copies
//! between them, in five spellings that did not agree:
//!
//! ```text
//! if offset.saturating_add(items.len()) < total { Some(..) } else { None }   // ida, 8 sites
//! if offset + functions.len() < total { Some(..) } else { None }             // ida, no saturation
//! truncated.then(|| offset + xrefs.len())                                    // ida, different premise
//! (offset + items.len() < total).then_some(..).filter(|_| !items.is_empty()) // bn, 13 sites
//! (total > consumed).then_some(consumed)                                     // ida, bounded scans
//! ```
//!
//! They differ in the cases nobody types by hand: `limit = 0`, an `offset` past
//! the end, a page that stopped at a scan ceiling. Each of those turns into a
//! `next_offset` that does not advance — a client that follows it politely asks
//! for the same page until it gives up. [`next_offset`] is the one definition,
//! and it says no in all three.

use crate::OutOfRange;

/// A page cut out of a longer answer, carrying what the caller needs to ask for
/// the rest of it.
///
/// Not a response type. Engines publish their own field names — `functions`,
/// `refs`, `matches` — and a client reads those names out of a schema that was
/// stable before this crate existed. What travels here is the arithmetic; the
/// three fields are unpacked into whatever the tool already publishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    /// The entries in this page, in the order the collection had them.
    pub items: Vec<T>,
    /// How many entries exist in total, not how many are in `items`.
    ///
    /// The distinction is the whole point of the type: reporting `items.len()`
    /// here is exactly the bug this module exists to stop.
    pub total: usize,
    /// Where the next page starts, or `None` when this page ended the answer.
    pub next_offset: Option<usize>,
}

impl<T> Page<T> {
    /// Cut a page out of a collection that is already complete in memory.
    ///
    /// The common case: the tool gathered everything, and paging is a courtesy
    /// to the caller's context window rather than a property of the scan.
    pub fn of(all: Vec<T>, offset: usize, limit: usize) -> Self {
        let total = all.len();
        let items: Vec<T> = all.into_iter().skip(offset).take(limit).collect();
        Self {
            next_offset: next_offset(offset, items.len(), total),
            total,
            items,
        }
    }

    /// A page that was cut *during* the walk, with the count kept separately.
    ///
    /// For scans that cannot afford to materialise the whole collection —
    /// walking a database's name table, say, where the page is filled as the
    /// walk goes and a counter tracks everything that matched. Those already
    /// know their total; what they historically dropped on the floor is this.
    pub fn counted(items: Vec<T>, offset: usize, total: usize) -> Self {
        Self {
            next_offset: next_offset(offset, items.len(), total),
            total,
            items,
        }
    }

    /// Was anything held back?
    ///
    /// `next_offset.is_some()` answers "can I ask for more"; this answers "is
    /// what I am holding the whole answer", and the two differ on the last
    /// page of an incomplete scan.
    pub fn is_truncated(&self) -> bool {
        self.items.len() < self.total
    }
}

/// Where the next page starts, or `None` when this page ended the answer.
///
/// The single definition. Two conditions, and the second is the one every
/// hand-written copy forgot:
///
/// - `offset + returned < total` — there is something past this page.
/// - `returned > 0` — this page moved. A `limit` of zero, or an `offset` past
///   the end, would otherwise hand back the offset it was given, and a client
///   that follows `next_offset` until it is `None` would follow that one
///   forever.
///
/// Saturating, because `offset` arrives from the wire: `usize::MAX` is a number
/// a caller can send, and it must produce "no next page" rather than a panic in
/// debug and a wrapped offset in release.
pub fn next_offset(offset: usize, returned: usize, total: usize) -> Option<usize> {
    let consumed = offset.saturating_add(returned);
    (returned > 0 && consumed < total).then_some(consumed)
}

/// Resolve the wire's `offset` and `limit` into the numbers a tool counts in.
///
/// `offset` and `limit` are refused and clamped respectively, and the asymmetry
/// is deliberate. Asking for a million entries is a well-formed question with an
/// unreasonable answer, so it gets the largest reasonable one. Asking for entry
/// -5 is not a question, and [`crate::parse_unsigned`] refuses it rather than
/// letting `-5i64 as usize` answer with an empty page that reads exactly like
/// the end of the list.
///
/// The lower clamp on `limit` is not decoration either: `limit = 0` yields an
/// empty page, and an empty page cannot advance, so a caller paging through a
/// listing with `limit = 0` receives nothing and is told nothing is left. One
/// entry is the smallest honest page.
pub fn bounds(
    offset: Option<i64>,
    limit: Option<i64>,
    default: usize,
    max: usize,
) -> Result<(usize, usize), OutOfRange> {
    let offset = crate::parse_optional_unsigned::<usize>(offset, "offset")?.unwrap_or(0);
    Ok((offset, capped(limit, default, max)))
}

/// A page size the tool will actually serve, from whatever arrived.
///
/// Split out because a handful of tools take a `limit` without an `offset` —
/// they cap a scan rather than page through it — and the clamp is what makes
/// the conversion total: whatever the caller sent, what comes out is in
/// `1..=max`, so no `TryFrom` can fail and no error path has to exist.
pub fn capped(limit: Option<i64>, default: usize, max: usize) -> usize {
    let max = max.max(1);
    let default = default.clamp(1, max);
    match limit {
        Some(limit) => limit.clamp(1, max as i64) as usize,
        None => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_page_with_more_behind_it_advances() {
        let page = Page::of((0..250).collect(), 0, 100);

        assert_eq!(page.items.len(), 100);
        assert_eq!(page.total, 250);
        assert_eq!(page.next_offset, Some(100));
        assert!(page.is_truncated());
    }

    #[test]
    fn the_page_that_reaches_the_end_stops() {
        let page = Page::of((0..250).collect(), 200, 100);

        assert_eq!(page.items.len(), 50);
        assert_eq!(page.total, 250);
        assert_eq!(page.next_offset, None);
    }

    /// The three shapes that produce a `next_offset` which does not advance.
    ///
    /// All three are reachable from the wire, and all three were spelled
    /// differently — or not handled — in the copies this replaced.
    #[test]
    fn a_page_that_did_not_move_never_offers_a_next_one() {
        // Nothing was asked for.
        assert_eq!(next_offset(0, 0, 250), None);
        // The offset is past everything there is.
        let page = Page::of((0..250).collect::<Vec<_>>(), 900, 100);
        assert!(page.items.is_empty());
        assert_eq!(page.next_offset, None);
        // The offset is a number a caller can type, and arithmetic on it must
        // not wrap.
        assert_eq!(next_offset(usize::MAX, 10, 250), None);
    }

    /// A scan that filled its page and stopped at its own ceiling.
    ///
    /// `total` equals what was returned, so there is nothing to advance into —
    /// the answer is incomplete, but `next_offset` is not the field that says
    /// so. The engine's own "this was a lower bound" flag is.
    #[test]
    fn a_page_that_is_all_the_scan_saw_does_not_invent_a_next_one() {
        let page = Page::counted((0..20_000).collect::<Vec<_>>(), 0, 20_000);

        assert_eq!(page.next_offset, None);
        assert!(!page.is_truncated());
    }

    /// The count comes from the walk, not from what the walk kept.
    #[test]
    fn a_streamed_page_reports_the_total_it_was_given() {
        // Filled entries 100..=199 of a table with 4,000 matches in it.
        let page = Page::counted((100..200).collect::<Vec<_>>(), 100, 4_000);

        assert_eq!(page.total, 4_000);
        assert_eq!(page.next_offset, Some(200));
        assert!(page.is_truncated());
    }

    #[test]
    fn a_negative_offset_is_refused_and_a_wild_limit_is_clamped() {
        assert!(bounds(Some(-1), None, 100, 10_000).is_err());
        assert_eq!(bounds(None, None, 100, 10_000), Ok((0, 100)));
        assert_eq!(
            bounds(Some(40), Some(1_000_000), 100, 10_000),
            Ok((40, 10_000))
        );
    }

    /// `limit = 0` is the request that pages forever, so it is not served.
    #[test]
    fn the_smallest_page_a_caller_can_ask_for_is_one_entry() {
        assert_eq!(capped(Some(0), 100, 10_000), 1);
        assert_eq!(capped(Some(-5), 100, 10_000), 1);
        assert_eq!(capped(Some(7), 100, 10_000), 7);

        let page = Page::of(
            (0..250).collect::<Vec<_>>(),
            0,
            capped(Some(0), 100, 10_000),
        );
        assert_eq!(page.next_offset, Some(1), "a served page always advances");
    }

    /// A default outside the engine's own ceiling is the engine's bug, but it
    /// is not worth a panic in a request path: the ceiling wins.
    #[test]
    fn a_default_larger_than_the_maximum_is_brought_back_inside_it() {
        assert_eq!(capped(None, 5_000, 100), 100);
        assert_eq!(capped(None, 0, 100), 1);
    }
}
