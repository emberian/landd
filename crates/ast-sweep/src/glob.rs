//! Path and name patterns.
//!
//! `*` matches any run of characters, `/` included (as `fnmatch` does, and as
//! `gateaudits.json` read patterns expect); `?` matches one character; `**/`
//! matches zero or more whole directories, so `tests/**/test_*.py` also
//! matches `tests/test_a.py`.

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Literal(u8),
    AnyOne,
    Star,
    /// `**/`: nothing, or anything ending in `/`.
    Dirs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Shape {
    Everything,
    Exact(String),
    /// `prefix*`
    Prefix(String),
    /// `*suffix`
    Suffix(String),
    General(Vec<Token>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Glob {
    shape: Shape,
}

impl Glob {
    pub fn new(pattern: &str) -> Self {
        let has_meta = |s: &str| s.contains(['*', '?']);
        let shape = if pattern == "*" || pattern == "**" {
            Shape::Everything
        } else if !has_meta(pattern) {
            Shape::Exact(pattern.to_owned())
        } else if let Some(prefix) = pattern.strip_suffix('*').filter(|p| !has_meta(p)) {
            Shape::Prefix(prefix.to_owned())
        } else if let Some(suffix) = pattern.strip_prefix('*').filter(|s| !has_meta(s)) {
            Shape::Suffix(suffix.to_owned())
        } else {
            Shape::General(tokenize(pattern.as_bytes()))
        };
        Self { shape }
    }

    /// The literal this pattern names, when it has no wildcard.
    pub fn exact(&self) -> Option<&str> {
        match &self.shape {
            Shape::Exact(exact) => Some(exact),
            _ => None,
        }
    }

    pub fn matches(&self, text: &str) -> bool {
        match &self.shape {
            Shape::Everything => true,
            Shape::Exact(exact) => text == exact,
            Shape::Prefix(prefix) => text.starts_with(prefix.as_str()),
            Shape::Suffix(suffix) => text.ends_with(suffix.as_str()),
            Shape::General(tokens) => match_tokens(tokens, text.as_bytes()),
        }
    }
}

fn tokenize(pattern: &[u8]) -> Vec<Token> {
    let mut tokens = Vec::with_capacity(pattern.len());
    let mut i = 0;
    while i < pattern.len() {
        match pattern[i] {
            b'*' if pattern[i..].starts_with(b"**/") && (i == 0 || pattern[i - 1] == b'/') => {
                tokens.push(Token::Dirs);
                i += 3;
                continue;
            }
            b'*' => {
                if tokens.last() != Some(&Token::Star) {
                    tokens.push(Token::Star);
                }
            }
            b'?' => tokens.push(Token::AnyOne),
            other => tokens.push(Token::Literal(other)),
        }
        i += 1;
    }
    tokens
}

fn match_tokens(tokens: &[Token], text: &[u8]) -> bool {
    let Some((first, rest)) = tokens.split_first() else {
        return text.is_empty();
    };
    match first {
        Token::Literal(byte) => text.first() == Some(byte) && match_tokens(rest, &text[1..]),
        Token::AnyOne => !text.is_empty() && match_tokens(rest, &text[1..]),
        Token::Star => rest.is_empty() || (0..=text.len()).any(|skip| match_tokens(rest, &text[skip..])),
        Token::Dirs => {
            match_tokens(rest, text)
                || text.iter().enumerate().any(|(i, byte)| *byte == b'/' && match_tokens(rest, &text[i + 1..]))
        }
    }
}

/// A set of patterns. An empty set matches nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GlobSet {
    globs: Vec<Glob>,
}

impl GlobSet {
    pub fn new<S: AsRef<str>>(patterns: &[S]) -> Self {
        Self { globs: patterns.iter().map(|p| Glob::new(p.as_ref())).collect() }
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

    /// Indices of the matching entries of `sorted`, which must be in byte
    /// order. Exact and prefix patterns are answered by binary search.
    pub fn select<S: AsRef<str>>(&self, sorted: &[S]) -> Vec<u32> {
        let mut picked = Vec::new();
        for glob in &self.globs {
            match &glob.shape {
                Shape::Everything => return (0..sorted.len() as u32).collect(),
                Shape::Exact(exact) => {
                    if let Ok(i) = sorted.binary_search_by(|probe| probe.as_ref().cmp(exact.as_str())) {
                        picked.push(i as u32);
                    }
                }
                Shape::Prefix(prefix) => {
                    let start = sorted.partition_point(|probe| probe.as_ref() < prefix.as_str());
                    picked.extend(
                        (start..sorted.len()).take_while(|i| sorted[*i].as_ref().starts_with(prefix.as_str())).map(|i| i as u32),
                    );
                }
                _ => picked
                    .extend(sorted.iter().enumerate().filter(|(_, s)| glob.matches(s.as_ref())).map(|(i, _)| i as u32)),
            }
        }
        picked.sort_unstable();
        picked.dedup();
        picked
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
    fn select_agrees_with_matches() {
        let paths = ["a.py", "fabd/a.py", "fabd/b/c.py", "fabd2/x.py", "land/x.py", "unchanged.py"];
        for patterns in [vec!["fabd/*", "unchanged.py"], vec!["*"], vec!["*.py"], vec!["**/x.py"], vec!["nope"], vec![]] {
            let set = GlobSet::new(&patterns);
            let slow: Vec<u32> =
                paths.iter().enumerate().filter(|(_, p)| set.matches(p)).map(|(i, _)| i as u32).collect();
            assert_eq!(set.select(&paths), slow, "{patterns:?}");
        }
        assert!(!GlobSet::default().matches("x"));
    }
}
