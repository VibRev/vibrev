//! A unified diff, for showing what a direct write is about to do.
//!
//! Written out rather than pulled in as a dependency: the whole job is a handful
//! of lines against a file we already hold in memory, and the preview is the one
//! thing standing between the user and an edit to a file they care about, so it
//! should have no surprises in it.
//!
//! `~/.claude.json` runs to thousands of lines, which rules out a naive O(n·m)
//! LCS. Trimming the common prefix and suffix first — always nearly the whole file
//! for a targeted edit — leaves a window small enough that the quadratic step is
//! free.

/// Context lines around each change, as `diff -u` uses.
const CONTEXT: usize = 3;

/// Above this many changed lines on either side, fall back to a summary rather
/// than allocating a large DP table for a diff nobody would read anyway.
const MAX_WINDOW: usize = 2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Ctx,
    Del,
    Ins,
}

/// A unified diff of `old` → `new`, or an empty string when they are identical.
pub fn unified(old: &str, new: &str, label: &str) -> String {
    if old == new {
        return String::new();
    }
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();

    let max_common = a.len().min(b.len());
    let prefix = (0..max_common).take_while(|&i| a[i] == b[i]).count();
    let suffix = (0..max_common - prefix)
        .take_while(|&i| a[a.len() - 1 - i] == b[b.len() - 1 - i])
        .count();

    let aw = &a[prefix..a.len() - suffix];
    let bw = &b[prefix..b.len() - suffix];

    if aw.len() > MAX_WINDOW || bw.len() > MAX_WINDOW {
        return format!(
            "--- {label}\n+++ {label}\n@@ 变更过大，未展开：删除 {} 行，新增 {} 行 @@\n",
            aw.len(),
            bw.len()
        );
    }

    // (kind, old line no, new line no, text), 1-based line numbers.
    let mut script: Vec<(Kind, usize, usize, &str)> = Vec::new();
    for (i, line) in a.iter().enumerate().take(prefix) {
        script.push((Kind::Ctx, i + 1, i + 1, line));
    }
    let mut ai = prefix;
    let mut bi = prefix;
    for (kind, text) in lcs_script(aw, bw) {
        match kind {
            Kind::Ctx => {
                script.push((Kind::Ctx, ai + 1, bi + 1, text));
                ai += 1;
                bi += 1;
            }
            Kind::Del => {
                script.push((Kind::Del, ai + 1, bi + 1, text));
                ai += 1;
            }
            Kind::Ins => {
                script.push((Kind::Ins, ai + 1, bi + 1, text));
                bi += 1;
            }
        }
    }
    for i in 0..suffix {
        script.push((Kind::Ctx, ai + i + 1, bi + i + 1, a[a.len() - suffix + i]));
    }

    render(&script, label)
}

/// Longest-common-subsequence edit script over two small slices.
fn lcs_script<'a>(a: &[&'a str], b: &[&'a str]) -> Vec<(Kind, &'a str)> {
    if a.is_empty() {
        return b.iter().map(|l| (Kind::Ins, *l)).collect();
    }
    if b.is_empty() {
        return a.iter().map(|l| (Kind::Del, *l)).collect();
    }

    let (n, m) = (a.len(), b.len());
    // dp[i][j] = LCS length of a[i..] and b[j..]; the extra row/column is the
    // empty-suffix base case, which is what lets the walk below run forwards.
    let mut dp = vec![0u32; (n + 1) * (m + 1)];
    let at = |i: usize, j: usize| i * (m + 1) + j;
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[at(i, j)] = if a[i] == b[j] {
                dp[at(i + 1, j + 1)] + 1
            } else {
                dp[at(i + 1, j)].max(dp[at(i, j + 1)])
            };
        }
    }

    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if a[i] == b[j] {
            out.push((Kind::Ctx, a[i]));
            i += 1;
            j += 1;
        } else if dp[at(i + 1, j)] >= dp[at(i, j + 1)] {
            out.push((Kind::Del, a[i]));
            i += 1;
        } else {
            out.push((Kind::Ins, b[j]));
            j += 1;
        }
    }
    out.extend(a[i..].iter().map(|l| (Kind::Del, *l)));
    out.extend(b[j..].iter().map(|l| (Kind::Ins, *l)));
    out
}

/// Group the script into `@@` hunks, keeping [`CONTEXT`] lines on each side.
fn render(script: &[(Kind, usize, usize, &str)], label: &str) -> String {
    let keep: Vec<bool> = {
        let mut keep = vec![false; script.len()];
        for (idx, (kind, ..)) in script.iter().enumerate() {
            if *kind == Kind::Ctx {
                continue;
            }
            let lo = idx.saturating_sub(CONTEXT);
            let hi = (idx + CONTEXT + 1).min(script.len());
            keep[lo..hi].fill(true);
        }
        keep
    };

    let mut out = format!("--- {label}\n+++ {label}\n");
    let mut idx = 0;
    while idx < script.len() {
        if !keep[idx] {
            idx += 1;
            continue;
        }
        let start = idx;
        while idx < script.len() && keep[idx] {
            idx += 1;
        }
        let hunk = &script[start..idx];

        let (mut old_n, mut new_n) = (0usize, 0usize);
        for (kind, ..) in hunk {
            match kind {
                Kind::Ctx => {
                    old_n += 1;
                    new_n += 1;
                }
                Kind::Del => old_n += 1,
                Kind::Ins => new_n += 1,
            }
        }
        // An all-insert hunk starts "after" line `old_start - 1`, which unified
        // diff spells as a zero length at the preceding line.
        let (_, a_line, b_line, _) = hunk[0];
        out.push_str(&format!(
            "@@ -{},{} +{},{} @@\n",
            if old_n == 0 { a_line - 1 } else { a_line },
            old_n,
            if new_n == 0 { b_line - 1 } else { b_line },
            new_n
        ));
        for (kind, _, _, text) in hunk {
            let sign = match kind {
                Kind::Ctx => ' ',
                Kind::Del => '-',
                Kind::Ins => '+',
            };
            out.push(sign);
            out.push_str(text);
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_input_produces_nothing() {
        assert_eq!(unified("a\nb\n", "a\nb\n", "f"), "");
    }

    #[test]
    fn a_one_line_change_shows_as_one_hunk() {
        let old = "1\n2\n3\n4\n5\n6\n7\n8\n9\n";
        let new = "1\n2\n3\n4\nFIVE\n6\n7\n8\n9\n";
        let d = unified(old, new, "f.json");
        assert_eq!(
            d,
            "--- f.json\n+++ f.json\n@@ -2,7 +2,7 @@\n 2\n 3\n 4\n-5\n+FIVE\n 6\n 7\n 8\n"
        );
    }

    #[test]
    fn distant_changes_get_separate_hunks() {
        let old = (1..=40)
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let mut lines: Vec<String> = (1..=40).map(|i| i.to_string()).collect();
        lines[1] = "TWO".into();
        lines[35] = "THIRTYSIX".into();
        let new = lines.join("\n");
        let d = unified(&old, &new, "f");
        assert_eq!(d.matches("@@ ").count(), 2);
        assert!(d.contains("-2\n+TWO\n"));
        assert!(d.contains("-36\n+THIRTYSIX\n"));
        // The untouched middle is not printed.
        assert!(!d.contains("\n 20\n"));
    }

    #[test]
    fn creating_a_file_is_all_additions() {
        let d = unified("", "{\n  \"a\": 1\n}\n", "new.json");
        assert!(d.contains("@@ -0,0 +1,3 @@"));
        assert!(d.contains("+{"));
        assert!(d.contains("+  \"a\": 1"));
        // Body lines are all additions; only the `---` header starts with a dash.
        let deletions = d.lines().skip(2).filter(|l| l.starts_with('-')).count();
        assert_eq!(deletions, 0, "nothing to delete: {d}");
    }

    #[test]
    fn a_huge_change_degrades_to_a_summary() {
        let old = (0..5000)
            .map(|i| format!("a{i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let new = (0..5000)
            .map(|i| format!("b{i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let d = unified(&old, &new, "big.json");
        assert!(d.contains("变更过大"));
    }

    /// The trimming shortcut must not change the answer for a big file with a
    /// small edit — this is the shape every real `~/.claude.json` write has.
    #[test]
    fn a_small_edit_in_a_big_file_is_still_exact() {
        let mut lines: Vec<String> = (0..20_000).map(|i| format!("line {i}")).collect();
        let old = lines.join("\n");
        lines[10_000] = "line CHANGED".into();
        let new = lines.join("\n");
        let d = unified(&old, &new, "big.json");
        assert_eq!(d.matches("@@ ").count(), 1);
        assert!(d.contains("-line 10000\n+line CHANGED\n"));
    }
}
