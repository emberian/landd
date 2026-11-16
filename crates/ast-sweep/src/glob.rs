//! Path and name patterns, in two dialects.
//!
//! * **fnmatch** ([`Glob::new`]): `*` matches any run of characters, `/`
//!   included, as `fnmatch` does and as `gateaudits.json` read patterns
//!   expect; `?` matches one character; `**/` matches zero or more whole
//!   directories, so `tests/**/test_*.py` also matches `tests/test_a.py`.
//! * **segment-aware** ([`Glob::segments`]): `*` and `?` stay inside one path
//!   segment and `**` crosses `/`, as `pathlib` globs and git pathspecs read
//!   them. Derived reads use this dialect, so `REPO.glob("*.py")` is the
//!   root's own Python files and not every one in the tree.
//!
//! Matching is a table walk, linear in pattern length times text length; no
//! pattern can make it backtrack exponentially.

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Literal(u8),
    /// One character (not `/` when `stay`).
    AnyOne {
        stay: bool,
    },
    /// Any run of characters (without `/` when `stay`).
    Star {
        stay: bool,
    },
    /// `**/`: nothing, or anything ending in `/`.
    Dirs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Shape {
    Everything,
    Exact(String),
    /// `prefix*` in the fnmatch dialect.
    Prefix(String),
    /// `*suffix` in the fnmatch dialect.
    Suffix(String),
    General {
        literal_prefix: String,
        tokens: Vec<Token>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Glob {
    shape: Shape,
}

fn has_meta(text: &str) -> bool {
    text.contains(['*', '?'])
}

impl Glob {
    /// The fnmatch dialect.
    pub fn new(pattern: &str) -> Self {
        let shape = if pattern == "*" || pattern == "**" {
            Shape::Everything
        } else if !has_meta(pattern) {
            Shape::Exact(pattern.to_owned())
        } else if let Some(prefix) = pattern.strip_suffix('*').filter(|p| !has_meta(p)) {
            Shape::Prefix(prefix.to_owned())
        } else if let Some(suffix) = pattern.strip_prefix('*').filter(|s| !has_meta(s)) {
            Shape::Suffix(suffix.to_owned())
        } else {
            Self::general(pattern, false)
        };
        Self { shape }
    }

    /// The segment-aware dialect.
    pub fn segments(pattern: &str) -> Self {
        let shape = if pattern == "**" {
            Shape::Everything
        } else if !has_meta(pattern) {
            Shape::Exact(pattern.to_owned())
        } else if let Some(prefix) = pattern.strip_suffix("/**").filter(|p| !has_meta(p)) {
            // Everything below a directory.
            Shape::Prefix(format!("{prefix}/"))
        } else {
            Self::general(pattern, true)
        };
        Self { shape }
    }

    fn general(pattern: &str, stay: bool) -> Shape {
        let cut = pattern.find(['*', '?']).unwrap_or(pattern.len());
        Shape::General { literal_prefix: pattern[..cut].to_owned(), tokens: tokenize(pattern.as_bytes(), stay) }
    }

    /// The literal this pattern names, when it has no wildcard.
    pub fn exact(&self) -> Option<&str> {
        match &self.shape {
            Shape::Exact(exact) => Some(exact),
            _ => None,
        }
    }

    pub fn is_everything(&self) -> bool {
        self.shape == Shape::Everything
    }

    /// The literal text every match starts with.
    fn literal_prefix(&self) -> &str {
        match &self.shape {
            Shape::Everything | Shape::Suffix(_) => "",
            Shape::Exact(text) | Shape::Prefix(text) => text,
            Shape::General { literal_prefix, .. } => literal_prefix,
        }
    }

    pub fn matches(&self, text: &str) -> bool {
        match &self.shape {
            Shape::Everything => true,
            Shape::Exact(exact) => text == exact,
            Shape::Prefix(prefix) => text.starts_with(prefix.as_str()),
            Shape::Suffix(suffix) => text.ends_with(suffix.as_str()),
            Shape::General { tokens, .. } => match_tokens(tokens, text.as_bytes()),
        }
    }
}

fn tokenize(pattern: &[u8], stay: bool) -> Vec<Token> {
    let mut tokens = Vec::with_capacity(pattern.len());
    let mut i = 0;
    while i < pattern.len() {
        match pattern[i] {
            b'*' if pattern[i..].starts_with(b"**/") && (i == 0 || pattern[i - 1] == b'/') => {
                tokens.push(Token::Dirs);
                i += 3;
                continue;
            }
            b'*' if pattern[i..].starts_with(b"**") => {
                // `**` not followed by `/` crosses directories in both dialects.
                if tokens.last() != Some(&Token::Star { stay: false }) {
                    tokens.push(Token::Star { stay: false });
                }
                i += 2;
                continue;
            }
            b'*' => {
                if tokens.last() != Some(&Token::Star { stay }) {
                    tokens.push(Token::Star { stay });
                }
            }
            b'?' => tokens.push(Token::AnyOne { stay }),
            other => tokens.push(Token::Literal(other)),
        }
        i += 1;
    }
    tokens
}

/// `reach[j]` after token `i`: the tokens so far can consume exactly the
/// first `j` bytes of `text`.
fn match_tokens(tokens: &[Token], text: &[u8]) -> bool {
    let n = text.len();
    let mut reach = vec![false; n + 1];
    reach[0] = true;
    let mut next = vec![false; n + 1];
    for token in tokens {
        next.iter_mut().for_each(|slot| *slot = false);
        match token {
            Token::Literal(byte) => {
                for j in 0..n {
                    next[j + 1] = reach[j] && text[j] == *byte;
                }
            }
            Token::AnyOne { stay } => {
                for j in 0..n {
                    next[j + 1] = reach[j] && !(*stay && text[j] == b'/');
                }
            }
            Token::Star { stay } => {
                let mut open = false;
                for j in 0..=n {
                    open |= reach[j];
                    next[j] = open;
                    if *stay && j < n && text[j] == b'/' {
                        open = false;
                    }
                }
            }
            Token::Dirs => {
                let mut open = false;
                for j in 0..=n {
                    // Zero directories, or any earlier start followed by a `/` just before `j`.
                    next[j] = reach[j] || (open && j > 0 && text[j - 1] == b'/');
                    open |= reach[j];
                }
            }
        }
        std::mem::swap(&mut reach, &mut next);
        if !reach.iter().any(|r| *r) {
            return false;
        }
    }
    reach[n]
}

/// A set of patterns. An empty set matches nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GlobSet {
    globs: Vec<Glob>,
}

impl GlobSet {
    /// fnmatch patterns.
    pub fn new<S: AsRef<str>>(patterns: &[S]) -> Self {
        Self { globs: patterns.iter().map(|p| Glob::new(p.as_ref())).collect() }
    }

    /// Segment-aware patterns.
    pub fn segments<S: AsRef<str>>(patterns: &[S]) -> Self {
        Self { globs: patterns.iter().map(|p| Glob::segments(p.as_ref())).collect() }
    }

    pub fn is_empty(&self) -> bool {
        self.globs.is_empty()
    }

    pub fn globs(&self) -> &[Glob] {
        &self.globs
    }

    pub fn matches(&self, text: &str) -> bool {
        self.globs.iter().any(|glob| glob.matches(text))
    }

    /// Whether some pattern matches everything.
    pub fn is_everything(&self) -> bool {
        self.globs.iter().any(Glob::is_everything)
    }

    /// Indices of the matching entries of `sorted`, which must be in byte
    /// order. Only the entries that share a pattern's literal prefix are
    /// examined, found by binary search.
    pub fn select<S: AsRef<str>>(&self, sorted: &[S]) -> Vec<u32> {
        let mut picked = Vec::new();
        for glob in &self.globs {
            select_one(glob, sorted, &mut picked);
        }
        picked.sort_unstable();
        picked.dedup();
        picked
    }
}

/// Append the indices of the entries of `sorted` that `glob` matches.
pub fn select_one<S: AsRef<str>>(glob: &Glob, sorted: &[S], picked: &mut Vec<u32>) {
    if glob.is_everything() {
        picked.extend(0..sorted.len() as u32);
        return;
    }
    let prefix = glob.literal_prefix();
    let start = sorted.partition_point(|probe| probe.as_ref() < prefix);
    for (offset, entry) in sorted[start..].iter().enumerate() {
        if !entry.as_ref().starts_with(prefix) {
            break;
        }
        if glob.matches(entry.as_ref()) {
            picked.push((start + offset) as u32);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn star_crosses_directories_like_fnmatch() {
        assert!(Glob::new("fabd/*").matches("fabd/deep/er/x.py"));
        assert!(Glob::new("*.pyc").matches("a/b/c.pyc"));
        assert!(Glob::new("*").matches("anything/at/all"));
        assert!(Glob::new("a?c").matches("abc"));
        assert!(!Glob::new("a?c").matches("ac"));
        assert!(Glob::new("land/*/x_*.py").matches("land/a/b/x_1.py"));
        assert!(!Glob::new("land/*.py").matches("fabd/a.py"));
        assert!(Glob::new("exact/path.py").matches("exact/path.py"));
        assert!(!Glob::new("exact/path.py").matches("exact/path.pyc"));
    }

    #[test]
    fn double_star_slash_matches_zero_or_more_directories() {
        let glob = Glob::new("tests/**/test_*.py");
        assert!(glob.matches("tests/test_a.py"));
        assert!(glob.matches("tests/door/deep/test_a.py"));
        assert!(!glob.matches("tests/door/helper.py"));
        assert!(!glob.matches("other/test_a.py"));
        let anywhere = Glob::new("**/conftest.py");
        assert!(anywhere.matches("conftest.py") && anywhere.matches("a/b/conftest.py"));
        assert!(!anywhere.matches("a/b/not_conftest.py"));
    }

    #[test]
    fn segment_aware_stars_stay_inside_one_segment() {
        let own = Glob::segments("*.py");
        assert!(own.matches("a.py") && !own.matches("pkg/a.py"));
        let level = Glob::segments("fleetd/*");
        assert!(level.matches("fleetd/a.py") && !level.matches("fleetd/sub/a.py") && !level.matches("fleetd"));
        let subtree = Glob::segments("fleetd/**");
        assert!(subtree.matches("fleetd/a.py") && subtree.matches("fleetd/sub/deep/a.py") && !subtree.matches("fleetd2/a.py"));
        let rglob = Glob::segments("tests/**/*.json");
        assert!(rglob.matches("tests/a.json") && rglob.matches("tests/x/y/a.json") && !rglob.matches("tests/x/a.py"));
        assert!(Glob::segments("a/?.txt").matches("a/b.txt") && !Glob::segments("a/?.txt").matches("a//.txt"));
        assert!(Glob::segments("**").matches("any/thing") && Glob::segments("**").is_everything());
        assert!(Glob::segments("docs/**/x").matches("docs/x") && Glob::segments("docs/**/x").matches("docs/a/b/x"));
        assert!(Glob::segments("a/**b").matches("a/x/yb"));
    }

    #[test]
    fn select_agrees_with_matches() {
        let paths = ["a.py", "fabd/a.py", "fabd/b/c.py", "fabd2/x.py", "land/x.py", "unchanged.py"];
        for patterns in
            [vec!["fabd/*", "unchanged.py"], vec!["*"], vec!["*.py"], vec!["**/x.py"], vec!["nope"], vec![], vec!["fabd*/?.py"]]
        {
            for set in [GlobSet::new(&patterns), GlobSet::segments(&patterns)] {
                let slow: Vec<u32> = paths.iter().enumerate().filter(|(_, p)| set.matches(p)).map(|(i, _)| i as u32).collect();
                assert_eq!(set.select(&paths), slow, "{patterns:?}");
            }
        }
        assert!(!GlobSet::default().matches("x"));
        assert!(GlobSet::new(&["a", "*"]).is_everything() && !GlobSet::new(&["a/*"]).is_everything());
    }

    /// A pattern of many stars against a long non-matching path used to
    /// take time exponential in the number of stars.
    #[test]
    fn tooth_many_stars_match_in_linear_time() {
        let pattern = format!("{}b", "*a".repeat(40));
        let text = "a".repeat(4000);
        let started = std::time::Instant::now();
        assert!(!Glob::new(&pattern).matches(&text));
        assert!(!Glob::segments(&pattern).matches(&text));
        assert!(Glob::new(&pattern).matches(&format!("{text}b")));
        assert!(started.elapsed() < std::time::Duration::from_secs(2), "{:?}", started.elapsed());
    }
}
