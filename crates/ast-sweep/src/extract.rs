//! The per-blob `Map` pass: bytes in, [`FileFacts`] out.
//!
//! Python is parsed with tree-sitter, which recovers from syntax errors, so a
//! half-broken file still yields the facts of everything that did parse (and
//! is marked `parse_error`, which widens every cone that reaches it). Recipe
//! files are scanned by line.
//!
//! # Paths
//!
//! Every read of the tree as data (an `open`, an existence probe, a listing,
//! a walk, a glob, a module loaded by path, a child process) is recorded with
//! the [`Reach`] of its path expression: the places the expression can name,
//! as far as literals say. A path is built from `__file__`, the working
//! directory, a string literal, or a name imported from another module, by
//! `/`, `os.path.join`, `Path()`, `.parent`, `.parents[n]`, `dirname` and
//! friends. Names are followed through assignments anywhere in the module
//! (flow-insensitively), `with … as`, loops over literal tuples and calls of
//! module-level functions. `tempfile` results are provably not the tree.
//! Everything else (a parameter, an attribute of an object, the result of an
//! unknown call) is *opaque*, and what the tree's readers do with an opaque
//! or unresolved read is a policy of the cone model, not of this pass.
//!
//! # Heuristics
//!
//! Two lint facts are heuristics over source text and say so here: a loop
//! "sleeps" when its text contains `sleep(`, and a sleeping loop is
//! "bounded" when it is a `for` or its text mentions a bound (`deadline`,
//! `timeout`, `monotonic(`, `time.time(`, `attempt`, `retries`, `tries`).
//! They feed the `flock_bounded` lint only; no cone depends on them.

use crate::facts::*;
use landd_core::Digest32;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use tree_sitter::{Node, Parser};

/// Deeper syntax than this is not walked; the file is marked `truncated`.
const MAX_DEPTH: usize = 1200;
/// A path expression nested deeper than this is opaque.
const MAX_PATH_DEPTH: usize = 48;
/// More alternatives than this for one path and it is unknown.
const MAX_PLACES: usize = 32;
/// Passes of the binding fixpoint; each pass only grows the bindings.
const PASSES: usize = 8;
const BOUND_HINTS: [&str; 7] = ["deadline", "timeout", "monotonic(", "time.time(", "attempt", "retries", "tries"];
const BODY_HASH_DOMAIN: &str = "ast-sweep function body v1";
/// Modules whose wildcard import can hide a loader or a scan behind a bare name.
const SENSITIVE_WILDCARDS: [&str; 12] = [
    "importlib",
    "importlib.util",
    "builtins",
    "os",
    "os.path",
    "runpy",
    "imp",
    "pkgutil",
    "subprocess",
    "shutil",
    "glob",
    "pathlib",
];

thread_local! {
    static PARSER: RefCell<Parser> = RefCell::new({
        let mut parser = Parser::new();
        parser.set_language(&tree_sitter_python::LANGUAGE.into()).expect("the python grammar loads");
        parser
    });
}

pub fn extract(kind: FileKind, source: &[u8]) -> FileFacts {
    match kind {
        FileKind::Python => extract_python(source),
        FileKind::TypeScript | FileKind::Tsx | FileKind::Lean | FileKind::Rust => crate::modules::extract(kind, source),
        FileKind::Recipe => extract_recipe(source),
        FileKind::Sniff => {
            let first = source.split(|b| *b == b'\n').next().unwrap_or_default();
            let shebang = std::str::from_utf8(first).ok().and_then(|line| line.strip_prefix("#!")).unwrap_or("");
            let interpreter = shebang.rsplit('/').next().unwrap_or("");
            if shebang.contains("python") {
                extract_python(source)
            } else if ["sh", "bash", "zsh", "dash", "ksh"].iter().any(|sh| {
                interpreter == *sh || interpreter.starts_with(&format!("{sh} ")) || shebang.ends_with(&format!("env {sh}"))
            }) {
                extract_recipe(source)
            } else {
                FileFacts::default()
            }
        }
        FileKind::Link => match std::str::from_utf8(source) {
            Ok(target) => FileFacts { link_target: Some(target.to_owned()), ..FileFacts::default() },
            Err(_) => FileFacts { parse_error: true, ..FileFacts::default() },
        },
    }
}

fn extract_python(source: &[u8]) -> FileFacts {
    // CPython ignores a UTF-8 byte order mark; tree-sitter would not.
    let source = source.strip_prefix(b"\xef\xbb\xbf").unwrap_or(source);
    let base = FileFacts { language: Language::Python, ..FileFacts::default() };
    let Some(tree) = PARSER.with(|parser| parser.borrow_mut().parse(source, None)) else {
        return FileFacts { parse_error: true, ..base };
    };
    let root = tree.root_node();
    let mut walker = Walker {
        src: source,
        // Source that is not UTF-8 (or declares another coding) cannot be
        // trusted to mean what its bytes say here.
        facts: FileFacts { parse_error: root.has_error() || std::str::from_utf8(source).is_err(), ..base },
        bad_text: Cell::new(false),
        aliases: HashMap::new(),
        symbols: BTreeMap::new(),
        scope: Vec::new(),
        fn_depth: 0,
        defined_top: BTreeSet::new(),
        non_import_top: HashSet::new(),
        plain_classes: HashSet::new(),
        rebound_names: HashSet::new(),
        symbol_deps: BTreeSet::new(),
        internal_calls: BTreeSet::new(),
        direct_call_sites: HashMap::new(),
        external_refs: BTreeSet::new(),
        scoped_calls: BTreeSet::new(),
        loops: Vec::new(),
        caught: Vec::new(),
        env: HashMap::new(),
        literals: HashMap::new(),
        own_params: HashSet::new(),
        nested_params: HashSet::new(),
        globals_in_owner: HashSet::new(),
    };
    walker.prepare(root);
    walker.visit(root, 0);
    let Walker { mut facts, symbols, bad_text, defined_top, symbol_deps, internal_calls, external_refs, scoped_calls, .. } =
        walker;
    facts.parse_error |= bad_text.get();
    facts.symbols = symbols.into_iter().map(|((name, call), (line, count))| SymbolRef { name, call, line, count }).collect();
    facts.defined_symbols = defined_top.into_iter().collect();
    facts.symbol_deps = symbol_deps.into_iter().collect();
    facts.internal_calls = internal_calls.into_iter().collect();
    facts.external_refs = external_refs.into_iter().collect();
    facts.scoped_calls = scoped_calls.into_iter().collect();
    facts
}

/// The evaluator's working form of a [`Reach`], which also remembers that a
/// path is provably scratch or derived from the enclosing function's parameter.
#[derive(Clone, Default, PartialEq)]
struct R {
    places: Vec<Place>,
    unknown: bool,
    opaque: bool,
    own_param: bool,
    temp: bool,
}

impl R {
    fn opaque() -> Self {
        Self { opaque: true, ..Self::default() }
    }

    fn unknown() -> Self {
        Self { unknown: true, ..Self::default() }
    }

    fn temp() -> Self {
        Self { temp: true, ..Self::default() }
    }

    fn place(anchor: Anchor) -> Self {
        Self { places: vec![Place { anchor, up: 0, tail: String::new(), open: false }], ..Self::default() }
    }

    /// A literal path as the process sees it: relative to the working
    /// directory. An absolute path, or one that climbs out, is not the tree.
    fn literal(text: &str) -> Self {
        if text.starts_with('/') {
            return Self::default();
        }
        Self::place(Anchor::Root).join(text)
    }

    fn rooted(&self) -> bool {
        !self.places.is_empty() || self.unknown
    }

    fn is_nothing(&self) -> bool {
        !self.rooted() && !self.opaque && !self.own_param
    }

    /// Returns whether anything was added.
    fn merge(&mut self, other: R) -> bool {
        let before = (self.places.len(), self.unknown, self.opaque, self.own_param, self.temp);
        for place in other.places {
            if self.places.contains(&place) {
                continue;
            }
            if self.places.len() >= MAX_PLACES {
                self.unknown = true;
            } else {
                self.places.push(place);
            }
        }
        self.unknown |= other.unknown;
        self.opaque |= other.opaque;
        self.own_param |= other.own_param;
        self.temp |= other.temp;
        before != (self.places.len(), self.unknown, self.opaque, self.own_param, self.temp)
    }

    fn up(mut self, levels: usize) -> Self {
        let mut kept = Vec::with_capacity(self.places.len());
        for mut place in self.places.drain(..) {
            if place.open {
                // Above an unknown suffix: no longer a known place.
                self.unknown = true;
                continue;
            }
            for _ in 0..levels {
                match place.tail.rfind('/') {
                    Some(cut) => place.tail.truncate(cut),
                    None if !place.tail.is_empty() => place.tail.clear(),
                    None => place.up = place.up.saturating_add(1),
                }
            }
            kept.push(place);
        }
        self.places = kept;
        self.without_escapes()
    }

    /// Something unknown follows.
    fn opened(mut self) -> Self {
        for place in &mut self.places {
            place.open = true;
        }
        self
    }

    fn join(mut self, segment: &str) -> Self {
        if segment.starts_with('/') {
            // `os.path.join(base, "/abs")` is `/abs`: not the tree.
            self.places.clear();
            return self;
        }
        let mut kept = Vec::with_capacity(self.places.len());
        for mut place in self.places.drain(..) {
            if !place.open {
                for part in segment.split('/') {
                    match part {
                        "" | "." => {}
                        ".." => match place.tail.rfind('/') {
                            Some(cut) => place.tail.truncate(cut),
                            None if !place.tail.is_empty() => place.tail.clear(),
                            None => place.up = place.up.saturating_add(1),
                        },
                        part => {
                            if !place.tail.is_empty() {
                                place.tail.push('/');
                            }
                            place.tail.push_str(part);
                        }
                    }
                }
            }
            kept.push(place);
        }
        self.places = kept;
        self.without_escapes()
    }

    /// Above the root of the tree is not the tree.
    fn without_escapes(mut self) -> Self {
        self.places.retain(|place| !(place.anchor == Anchor::Root && place.up > 0));
        self
    }

    fn into_reach(self) -> Reach {
        Reach { places: self.places, unknown: self.unknown, opaque: self.opaque || self.own_param }
    }
}

struct Loop {
    sleeps: bool,
    bounded: bool,
}

struct Walker<'s> {
    src: &'s [u8],
    facts: FileFacts,
    /// Some node's text was not UTF-8.
    bad_text: Cell<bool>,
    /// Local name -> the dotted name it was imported as (leading dots: relative).
    aliases: HashMap<&'s str, String>,
    symbols: BTreeMap<(String, bool), (u32, u32)>,
    scope: Vec<&'s str>,
    /// Nesting inside deferred function/lambda bodies (`0` at module import time).
    fn_depth: usize,
    defined_top: BTreeSet<String>,
    /// Top-level names defined by `def`, `class`, or assignments (not solely imports).
    non_import_top: HashSet<String>,
    /// Undecorated top-level classes with no custom `__new__`/metaclass/bases.
    plain_classes: HashSet<String>,
    /// Names assigned anywhere, including heads of attribute writes.
    rebound_names: HashSet<String>,
    symbol_deps: BTreeSet<(String, String)>,
    internal_calls: BTreeSet<(String, String, bool)>,
    direct_call_sites: HashMap<usize, (String, String, bool)>,
    external_refs: BTreeSet<ScopedRef>,
    scoped_calls: BTreeSet<(String, String)>,
    loops: Vec<Loop>,
    /// Names bound by the enclosing `except … as name` clauses.
    caught: Vec<&'s str>,
    /// What each `(owner, var)` bound name may hold as a path.
    env: HashMap<(String, &'s str), R>,
    /// `(owner, var)` bound solely to literal strings.
    literals: HashMap<(String, &'s str), Vec<String>>,
    /// Parameters `(fn_name, param)` of top-level functions.
    own_params: HashSet<(String, &'s str)>,
    /// Parameters `(owner, param)` of methods, lambdas and nested functions.
    nested_params: HashSet<(String, &'s str)>,
    /// `global name` declarations inside `owner`.
    globals_in_owner: HashSet<(String, &'s str)>,
}

fn line_of(node: Node) -> u32 {
    node.start_position().row as u32 + 1
}

fn is_string(node: Node) -> bool {
    matches!(node.kind(), "string" | "concatenated_string")
}

/// A statement that is only a string: a docstring or a bare string.
fn is_string_statement(node: Node) -> bool {
    node.kind() == "expression_statement" && node.named_child_count() == 1 && node.named_child(0).is_some_and(is_string)
}

fn named<'t>(node: Node<'t>) -> Vec<Node<'t>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

/// The positional arguments of a call.
fn positional<'t>(call: Node<'t>) -> Vec<Node<'t>> {
    let Some(arguments) = call.child_by_field_name("arguments").filter(|a| a.kind() == "argument_list") else {
        return Vec::new();
    };
    named(arguments)
        .into_iter()
        .filter(|a| !matches!(a.kind(), "keyword_argument" | "comment" | "list_splat" | "dictionary_splat"))
        .collect()
}

/// Decode the body of a non-raw string literal the way Python does.
/// `None` for an escape this decoder does not know (`\N{…}`).
fn unescape(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let Some(escape) = chars.next() else {
            out.push('\\');
            break;
        };
        let hex = |digits: usize, chars: &mut std::iter::Peekable<std::str::Chars>| -> Option<char> {
            let text: String = (0..digits).map_while(|_| chars.next_if(|c| c.is_ascii_hexdigit())).collect();
            (text.len() == digits).then(|| u32::from_str_radix(&text, 16).ok().and_then(char::from_u32)).flatten()
        };
        match escape {
            '\n' => {}
            '\\' | '\'' | '"' => out.push(escape),
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'a' => out.push('\u{07}'),
            'b' => out.push('\u{08}'),
            'f' => out.push('\u{0c}'),
            'v' => out.push('\u{0b}'),
            'x' => out.push(hex(2, &mut chars)?),
            'u' => out.push(hex(4, &mut chars)?),
            'U' => out.push(hex(8, &mut chars)?),
            '0'..='7' => {
                let mut value = escape.to_digit(8)?;
                for _ in 0..2 {
                    match chars.next_if(|c| ('0'..='7').contains(c)) {
                        Some(digit) => value = value * 8 + digit.to_digit(8)?,
                        None => break,
                    }
                }
                out.push(char::from_u32(value)?);
            }
            'N' => return None,
            // Python keeps an unknown escape as written.
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    Some(out)
}

impl<'s> Walker<'s> {
    fn text(&self, node: Node) -> &'s str {
        match node.utf8_text(self.src) {
            Ok(text) => text,
            Err(_) => {
                self.bad_text.set(true);
                ""
            }
        }
    }

    fn func(&self) -> String {
        self.scope.join(".")
    }

    /// Top-level symbol owning the current deferred body, or `""` when
    /// evaluated at module import time.
    fn owner_for(plain_classes: &HashSet<String>, scope: &[&str], fn_depth: usize) -> String {
        if fn_depth == 0 {
            String::new()
        } else if scope.len() >= 2 && scope[1] == "__init__" && plain_classes.contains(scope[0]) {
            format!("{}.__init__", scope[0])
        } else {
            scope.first().copied().unwrap_or("").to_owned()
        }
    }

    fn owner(&self) -> String {
        Self::owner_for(&self.plain_classes, &self.scope, self.fn_depth)
    }

    fn collect_binding_targets(&mut self, node: Node) {
        match node.kind() {
            "identifier" => {
                let name = self.text(node);
                if !name.is_empty() {
                    self.defined_top.insert(name.to_owned());
                    self.non_import_top.insert(name.to_owned());
                }
            }
            "pattern_list"
            | "tuple_pattern"
            | "list_pattern"
            | "tuple"
            | "list"
            | "parenthesized_expression"
            | "list_splat_pattern"
            | "as_pattern" => {
                for child in named(node) {
                    self.collect_binding_targets(child);
                }
            }
            _ => {}
        }
    }

    fn collect_top_bindings(&mut self, node: Node) {
        match node.kind() {
            "function_definition" | "class_definition" => {
                if let Some(name) = node.child_by_field_name("name").map(|n| self.text(n)).filter(|n| !n.is_empty()) {
                    self.defined_top.insert(name.to_owned());
                    self.non_import_top.insert(name.to_owned());
                }
                return;
            }
            "lambda" | "list_comprehension" | "set_comprehension" | "dictionary_comprehension" | "generator_expression" => return,
            "import_statement" => {
                for child in named(node) {
                    match child.kind() {
                        "dotted_name" => {
                            let head = self.text(child).split('.').next().unwrap_or("");
                            if !head.is_empty() {
                                self.defined_top.insert(head.to_owned());
                            }
                        }
                        "aliased_import" => {
                            if let Some(alias) =
                                child.child_by_field_name("alias").map(|a| self.text(a)).filter(|a| !a.is_empty())
                            {
                                self.defined_top.insert(alias.to_owned());
                            }
                        }
                        _ => {}
                    }
                }
                return;
            }
            "import_from_statement" => {
                for (orig, local) in self.imported_names(node) {
                    if orig != "*" && !local.is_empty() {
                        self.defined_top.insert(local.to_owned());
                    }
                }
                return;
            }
            "assignment" | "augmented_assignment" => {
                if let Some(left) = node.child_by_field_name("left") {
                    self.collect_binding_targets(left);
                }
                return;
            }
            "named_expression" => {
                if let Some(name) = node.child_by_field_name("name") {
                    self.collect_binding_targets(name);
                }
                return;
            }
            "for_statement" => {
                if let Some(left) = node.child_by_field_name("left") {
                    self.collect_binding_targets(left);
                }
            }
            "with_item" => {
                if let Some(alias) = node
                    .child_by_field_name("value")
                    .filter(|v| v.kind() == "as_pattern")
                    .and_then(|p| p.child_by_field_name("alias"))
                {
                    self.collect_binding_targets(alias);
                }
                return;
            }
            "except_clause" => {
                let alias = node.child_by_field_name("alias").or_else(|| {
                    named(node).into_iter().find(|c| c.kind() == "as_pattern").and_then(|p| p.child_by_field_name("alias"))
                });
                if let Some(alias) = alias {
                    self.collect_binding_targets(alias);
                }
            }
            _ => {}
        }
        for child in named(node) {
            self.collect_top_bindings(child);
        }
    }

    fn site(&self, node: Node, what: impl Into<String>) -> Site {
        Site { line: line_of(node), func: self.func(), what: what.into() }
    }

    fn note(&mut self, name: String, call: bool, line: u32) {
        let entry = self.symbols.entry((name, call)).or_insert((line, 0));
        entry.1 += 1;
    }

    /// `a.b.c` for a chain of plain names; `None` when the chain starts at a
    /// call, a subscript or anything else.
    fn dotted(&self, node: Node) -> Option<String> {
        match node.kind() {
            "identifier" => Some(self.text(node).to_owned()),
            "attribute" => {
                let mut base = self.dotted(node.child_by_field_name("object")?)?;
                base.push('.');
                base.push_str(self.text(node.child_by_field_name("attribute")?));
                Some(base)
            }
            _ => None,
        }
    }

    fn resolve(&self, dotted: String) -> String {
        let head = dotted.split('.').next().unwrap_or("");
        match self.aliases.get(head) {
            Some(full) if full != head => format!("{full}{}", &dotted[head.len()..]),
            _ => dotted,
        }
    }

    /// The module an import names, and its leading dots.
    fn import_source(&self, node: Node) -> (u8, &'s str) {
        let (mut level, mut module) = (0u8, "");
        if let Some(source) = node.child_by_field_name("module_name") {
            if source.kind() == "relative_import" {
                for part in named(source) {
                    match part.kind() {
                        "import_prefix" => level = self.text(part).len().min(255) as u8,
                        "dotted_name" => module = self.text(part),
                        _ => {}
                    }
                }
            } else {
                module = self.text(source);
            }
        }
        (level, module)
    }

    /// `(imported name, local name)` of each name a `from` import binds.
    fn imported_names(&self, node: Node) -> Vec<(&'s str, &'s str)> {
        let mut cursor = node.walk();
        node.children_by_field_name("name", &mut cursor)
            .map(|child| match child.kind() {
                "aliased_import" => {
                    let name = child.child_by_field_name("name").map(|n| self.text(n)).unwrap_or("");
                    (name, child.child_by_field_name("alias").map(|a| self.text(a)).unwrap_or(name))
                }
                _ => (self.text(child), self.text(child)),
            })
            .collect()
    }

    /// The literal strings a node holds: a string, a tuple/list of strings,
    /// or a conditional whose branches both hold literal strings.
    fn string_values(&self, node: Node) -> Option<Vec<String>> {
        match node.kind() {
            "string" | "concatenated_string" => self.literal(node).map(|s| vec![s]),
            "tuple" | "list" => {
                let items = named(node);
                (!items.is_empty()).then(|| items.iter().map(|i| self.literal(*i)).collect::<Option<Vec<_>>>()).flatten()
            }
            "conditional_expression" => {
                let parts = named(node);
                if parts.len() == 3 {
                    let mut out = self.string_values(parts[0])?;
                    out.extend(self.string_values(parts[2])?);
                    Some(out)
                } else {
                    None
                }
            }
            "parenthesized_expression" => node.named_child(0).and_then(|inner| self.string_values(inner)),
            _ => None,
        }
    }

    fn parameter_specs<'t>(&self, parameters: Node<'t>) -> Vec<(&'s str, Option<Node<'t>>, bool)> {
        named(parameters)
            .into_iter()
            .filter_map(|p| match p.kind() {
                "identifier" => Some((self.text(p), None, false)),
                "default_parameter" | "typed_default_parameter" => {
                    let name = p.child_by_field_name("name")?;
                    Some((self.text(name), p.child_by_field_name("value"), false))
                }
                "typed_parameter" => {
                    let name = named(p).into_iter().find(|c| c.kind() == "identifier")?;
                    Some((self.text(name), None, false))
                }
                "list_splat_pattern" | "dictionary_splat_pattern" => {
                    let name = named(p).into_iter().find(|c| c.kind() == "identifier")?;
                    Some((self.text(name), None, true))
                }
                _ => None,
            })
            .collect()
    }

    fn detect_plain_classes(&mut self, root: Node) {
        for stmt in named(root) {
            if stmt.kind() == "class_definition" {
                let Some(cls_name) = stmt.child_by_field_name("name").map(|n| self.text(n)).filter(|n| !n.is_empty()) else {
                    continue;
                };
                if self.rebound_names.contains(cls_name) {
                    continue;
                }
                let ok_bases = match stmt.child_by_field_name("superclasses") {
                    None => true,
                    Some(supers) => {
                        let args = named(supers);
                        args.is_empty()
                            || (args.len() == 1
                                && args[0].kind() == "identifier"
                                && self.text(args[0]) == "object"
                                && !self.aliases.contains_key("object")
                                && !self.non_import_top.contains("object"))
                    }
                };
                if !ok_bases {
                    continue;
                }
                let mut ok_body = true;
                if let Some(body) = stmt.child_by_field_name("body") {
                    for member in named(body) {
                        match member.kind() {
                            "function_definition" => {
                                let m = member.child_by_field_name("name").map(|n| self.text(n)).unwrap_or("");
                                if m.starts_with("__") && m != "__init__" {
                                    ok_body = false;
                                    break;
                                }
                            }
                            "decorated_definition" => {
                                let inner = named(member).into_iter().find(|c| c.kind() != "decorator");
                                let m = inner.and_then(|d| d.child_by_field_name("name")).map(|n| self.text(n)).unwrap_or("");
                                if m.starts_with("__") {
                                    ok_body = false;
                                    break;
                                }
                            }
                            "pass_statement" | "comment" => {}
                            "expression_statement" if is_string_statement(member) => {}
                            // Class attributes may install descriptors or replace special methods.
                            _ => {
                                ok_body = false;
                                break;
                            }
                        }
                    }
                }
                if ok_body {
                    self.plain_classes.insert(cls_name.to_owned());
                    self.symbol_deps.insert((cls_name.to_owned(), format!("{cls_name}.__init__")));
                }
            }
        }
    }

    /// One pass over the whole module before the facts are read off it:
    /// import aliases, and what every bound name may hold as a path.
    fn prepare(&mut self, root: Node) {
        // First collect import aliases and global declarations across the AST.
        let mut import_stack = vec![root];
        while let Some(node) = import_stack.pop() {
            match node.kind() {
                "assignment" | "augmented_assignment" | "named_expression" => {
                    let left = node.child_by_field_name("left").or_else(|| node.child_by_field_name("name"));
                    if let Some(raw) = left.and_then(|n| self.dotted(n)) {
                        self.rebound_names.insert(raw.split('.').next().unwrap_or("").to_owned());
                    }
                }
                "import_statement" => {
                    for child in named(node) {
                        match child.kind() {
                            "dotted_name" => {
                                let head = self.text(child).split('.').next().unwrap_or("");
                                self.aliases.entry(head).or_insert_with(|| head.to_owned());
                            }
                            "aliased_import" => {
                                if let (Some(name), Some(alias)) =
                                    (child.child_by_field_name("name"), child.child_by_field_name("alias"))
                                {
                                    self.aliases.insert(self.text(alias), self.text(name).to_owned());
                                }
                            }
                            _ => {}
                        }
                    }
                }
                "import_from_statement" => {
                    let (level, module) = self.import_source(node);
                    let dots = ".".repeat(level as usize);
                    for (name, local) in self.imported_names(node) {
                        if !name.is_empty() {
                            let joiner = if module.is_empty() { "" } else { "." };
                            self.aliases.insert(local, format!("{dots}{module}{joiner}{name}"));
                        }
                    }
                }
                _ => {}
            }
            import_stack.extend(named(node));
        }

        self.collect_top_bindings(root);
        self.detect_plain_classes(root);

        type ParameterSpecs<'s, 't> = Vec<(&'s str, Option<Node<'t>>, bool)>;
        struct Prep<'s, 't> {
            bindings: Vec<((String, &'s str), String, Node<'t>)>,
            functions: HashMap<&'s str, ParameterSpecs<'s, 't>>,
            ambiguous_fns: HashSet<&'s str>,
            calls: Vec<(String, Node<'t>)>,
            loops_over_names: Vec<((String, &'s str), String, Node<'t>)>,
            not_literal: HashSet<(String, &'s str)>,
        }

        fn walk_globals<'s>(walker: &mut Walker<'s>, node: Node, scope: &mut Vec<&'s str>, fn_depth: usize, depth: usize) {
            if depth > MAX_DEPTH {
                return;
            }
            match node.kind() {
                "global_statement" => {
                    let cur = Walker::owner_for(&walker.plain_classes, scope, fn_depth);
                    for child in named(node) {
                        if child.kind() == "identifier" {
                            let name = walker.text(child);
                            if !name.is_empty() {
                                walker.defined_top.insert(name.to_owned());
                                walker.non_import_top.insert(name.to_owned());
                                if !cur.is_empty() {
                                    walker.globals_in_owner.insert((cur.clone(), name));
                                }
                            }
                        }
                    }
                    return;
                }
                "function_definition" => {
                    let fn_name = node.child_by_field_name("name").map(|n| walker.text(n)).unwrap_or("");
                    scope.push(fn_name);
                    if let Some(body) = node.child_by_field_name("body") {
                        walk_globals(walker, body, scope, fn_depth + 1, depth + 1);
                    }
                    scope.pop();
                    return;
                }
                "class_definition" => {
                    let cls_name = node.child_by_field_name("name").map(|n| walker.text(n)).unwrap_or("");
                    scope.push(cls_name);
                    if let Some(body) = node.child_by_field_name("body") {
                        walk_globals(walker, body, scope, fn_depth, depth + 1);
                    }
                    scope.pop();
                    return;
                }
                _ => {}
            }
            for child in named(node) {
                walk_globals(walker, child, scope, fn_depth, depth + 1);
            }
        }

        fn walk_prep<'s, 't>(
            walker: &mut Walker<'s>,
            node: Node<'t>,
            prep: &mut Prep<'s, 't>,
            scope: &mut Vec<&'s str>,
            fn_depth: usize,
            depth: usize,
        ) {
            if depth > MAX_DEPTH {
                return;
            }
            let cur = Walker::owner_for(&walker.plain_classes, scope, fn_depth);
            let var_key = |w: &Walker<'s>, cur: &str, name: &'s str| -> (String, &'s str) {
                if cur.is_empty() || w.globals_in_owner.contains(&(cur.to_owned(), name)) {
                    (String::new(), name)
                } else {
                    (cur.to_owned(), name)
                }
            };

            match node.kind() {
                "function_definition" => {
                    let fn_name = node.child_by_field_name("name").map(|n| walker.text(n)).unwrap_or("");
                    let specs = node.child_by_field_name("parameters").map(|p| walker.parameter_specs(p)).unwrap_or_default();
                    for (_, def_val, _) in &specs {
                        if let Some(val) = def_val {
                            walk_prep(walker, *val, prep, scope, fn_depth, depth + 1);
                        }
                    }
                    if let Some(ret) = node.child_by_field_name("return_type") {
                        walk_prep(walker, ret, prep, scope, fn_depth, depth + 1);
                    }
                    let top = fn_depth == 0
                        && scope.is_empty()
                        && node.parent().is_some_and(|p| {
                            p.kind() == "module"
                                || (p.kind() == "decorated_definition" && p.parent().is_some_and(|g| g.kind() == "module"))
                        });
                    scope.push(fn_name);
                    let body_owner = Walker::owner_for(&walker.plain_classes, scope, fn_depth + 1);
                    if top && !fn_name.is_empty() {
                        if prep.functions.contains_key(fn_name) {
                            prep.ambiguous_fns.insert(fn_name);
                            for (pname, _, _) in &specs {
                                walker.nested_params.insert((body_owner.clone(), *pname));
                            }
                        } else {
                            for (pname, def_val, _) in &specs {
                                walker.own_params.insert((body_owner.clone(), *pname));
                                if let Some(val) = def_val {
                                    prep.bindings.push(((body_owner.clone(), *pname), cur.clone(), *val));
                                }
                            }
                            prep.functions.insert(fn_name, specs);
                        }
                    } else {
                        for (pname, def_val, _) in specs.into_iter().filter(|(n, _, _)| !matches!(*n, "self" | "cls")) {
                            walker.nested_params.insert((body_owner.clone(), pname));
                            if let Some(val) = def_val {
                                prep.bindings.push(((body_owner.clone(), pname), cur.clone(), val));
                            }
                        }
                    }
                    if let Some(body) = node.child_by_field_name("body") {
                        walk_prep(walker, body, prep, scope, fn_depth + 1, depth + 1);
                    }
                    scope.pop();
                    return;
                }
                "lambda" => {
                    let specs = node.child_by_field_name("parameters").map(|p| walker.parameter_specs(p)).unwrap_or_default();
                    let mut pushed_target = false;
                    if fn_depth == 0 && scope.is_empty() {
                        if let Some(assign) = node.parent().filter(|p| p.kind() == "assignment") {
                            if let Some(left) = assign.child_by_field_name("left").filter(|l| l.kind() == "identifier") {
                                scope.push(walker.text(left));
                                pushed_target = true;
                            }
                        }
                    }
                    let body_owner = Walker::owner_for(&walker.plain_classes, scope, fn_depth + 1);
                    for (pname, def_val, _) in specs {
                        walker.nested_params.insert((body_owner.clone(), pname));
                        if let Some(val) = def_val {
                            prep.bindings.push(((body_owner.clone(), pname), cur.clone(), val));
                        }
                    }
                    if let Some(body) = node.child_by_field_name("body") {
                        walk_prep(walker, body, prep, scope, fn_depth + 1, depth + 1);
                    }
                    if pushed_target {
                        scope.pop();
                    }
                    return;
                }
                "class_definition" => {
                    let cls_name = node.child_by_field_name("name").map(|n| walker.text(n)).unwrap_or("");
                    if let Some(supers) = node.child_by_field_name("superclasses") {
                        walk_prep(walker, supers, prep, scope, fn_depth, depth + 1);
                    }
                    scope.push(cls_name);
                    if let Some(body) = node.child_by_field_name("body") {
                        walk_prep(walker, body, prep, scope, fn_depth, depth + 1);
                    }
                    scope.pop();
                    return;
                }
                "assignment" | "named_expression" => {
                    let (target, value) = if node.kind() == "assignment" {
                        (node.child_by_field_name("left"), node.child_by_field_name("right"))
                    } else {
                        (node.child_by_field_name("name"), node.child_by_field_name("value"))
                    };
                    if let (Some(target), Some(value)) = (target.filter(|t| t.kind() == "identifier"), value) {
                        let key = var_key(walker, &cur, walker.text(target));
                        prep.bindings.push((key.clone(), cur.clone(), value));
                        match walker.string_values(value) {
                            Some(values) => walker.literals.entry(key).or_default().extend(values),
                            None => {
                                prep.not_literal.insert(key);
                            }
                        }
                    }
                }
                "with_item" => {
                    let pattern = node.child_by_field_name("value").filter(|v| v.kind() == "as_pattern");
                    let alias = pattern.and_then(|p| p.child_by_field_name("alias"));
                    if let (Some(pattern), Some(alias)) = (pattern, alias) {
                        if let Some(value) = pattern.named_child(0) {
                            let key = var_key(walker, &cur, walker.text(alias));
                            prep.bindings.push((key.clone(), cur.clone(), value));
                            prep.not_literal.insert(key);
                        }
                    }
                }
                "for_statement" | "for_in_clause" => {
                    if let (Some(left), Some(right)) = (node.child_by_field_name("left"), node.child_by_field_name("right")) {
                        if left.kind() == "identifier" {
                            let key = var_key(walker, &cur, walker.text(left));
                            match (walker.string_values(right), right.kind()) {
                                (Some(values), _) => walker.literals.entry(key).or_default().extend(values),
                                (None, "tuple" | "list") => {
                                    prep.bindings
                                        .extend(named(right).into_iter().map(|element| (key.clone(), cur.clone(), element)));
                                    prep.not_literal.insert(key);
                                }
                                (None, "identifier") => prep.loops_over_names.push((key, cur.clone(), right)),
                                (None, _) => {
                                    prep.bindings.push((key.clone(), cur.clone(), right));
                                    prep.not_literal.insert(key);
                                }
                            }
                        } else {
                            let mut inner = vec![left];
                            while let Some(part) = inner.pop() {
                                if part.kind() == "identifier" {
                                    prep.not_literal.insert(var_key(walker, &cur, walker.text(part)));
                                }
                                inner.extend(named(part));
                            }
                        }
                    }
                }
                "call" if node.child_by_field_name("function").is_some_and(|f| f.kind() == "identifier") => {
                    prep.calls.push((cur.clone(), node));
                }
                _ => {}
            }
            for child in named(node) {
                walk_prep(walker, child, prep, &mut *scope, fn_depth, depth + 1);
            }
        }

        let mut scope = Vec::new();
        walk_globals(self, root, &mut scope, 0, 0);
        let mut prep = Prep {
            bindings: Vec::new(),
            functions: HashMap::new(),
            ambiguous_fns: HashSet::new(),
            calls: Vec::new(),
            loops_over_names: Vec::new(),
            not_literal: HashSet::new(),
        };
        scope.clear();
        walk_prep(self, root, &mut prep, &mut scope, 0, 0);
        for amb in &prep.ambiguous_fns {
            if let Some(specs) = prep.functions.remove(amb) {
                for (pname, _, _) in specs {
                    self.own_params.remove(&(amb.to_string(), pname));
                    self.nested_params.insert((amb.to_string(), pname));
                }
            }
        }

        let own_params = &self.own_params;
        let nested_params = &self.nested_params;
        for (key, iter_owner, iterable) in prep.loops_over_names {
            let source = self.text(iterable);
            let local_key = (iter_owner, source);
            let top_key = (String::new(), source);
            let found = if !local_key.0.is_empty()
                && (self.literals.contains_key(&local_key)
                    || prep.not_literal.contains(&local_key)
                    || own_params.contains(&local_key)
                    || nested_params.contains(&local_key))
            {
                self.literals
                    .get(&local_key)
                    .filter(|_| {
                        !prep.not_literal.contains(&local_key)
                            && !own_params.contains(&local_key)
                            && !nested_params.contains(&local_key)
                    })
                    .cloned()
            } else {
                self.literals.get(&top_key).filter(|_| !prep.not_literal.contains(&top_key)).cloned()
            };
            match found {
                Some(values) => self.literals.entry(key).or_default().extend(values),
                None => {
                    prep.bindings.push((key.clone(), local_key.0, iterable));
                    prep.not_literal.insert(key);
                }
            }
        }
        let not_literal = &prep.not_literal;
        let own_params = &self.own_params;
        let nested_params = &self.nested_params;
        self.literals.retain(|k, _| !not_literal.contains(k) && !own_params.contains(k) && !nested_params.contains(k));

        // Intra-module call bindings to top-level functions.
        let mut call_arg_bindings: Vec<((String, &'s str), String, Node)> = Vec::new();
        let mut splat_called: HashSet<&'s str> = HashSet::new();
        let mut candidate_direct_calls: Vec<(usize, &'s str, String, Vec<Node>)> = Vec::new();

        for (caller_owner, call) in prep.calls {
            let Some(callee_name) = call.child_by_field_name("function").map(|f| self.text(f)) else {
                continue;
            };
            let Some(specs) = prep.functions.get(callee_name) else {
                continue;
            };
            let args_node = call.child_by_field_name("arguments");
            let has_splat = args_node.into_iter().flat_map(named).any(|a| matches!(a.kind(), "list_splat" | "dictionary_splat"));
            if has_splat {
                splat_called.insert(callee_name);
                for (pname, _, _) in specs {
                    self.env.entry((callee_name.to_owned(), *pname)).or_default().opaque = true;
                }
                continue;
            }
            let non_var: Vec<(&'s str, bool)> =
                specs.iter().filter(|(_, _, var)| !*var).map(|(n, d, _)| (*n, d.is_some())).collect();
            let pos_args = positional(call);
            let mut supplied: HashSet<&'s str> = HashSet::new();
            let mut all_arg_nodes: Vec<Node> = Vec::new();
            for ((pname, _), val_node) in non_var.iter().zip(pos_args.iter()) {
                supplied.insert(*pname);
                all_arg_nodes.push(*val_node);
                call_arg_bindings.push(((callee_name.to_owned(), *pname), caller_owner.clone(), *val_node));
            }
            for extra in pos_args.iter().skip(non_var.len()) {
                all_arg_nodes.push(*extra);
            }
            if let Some(arguments) = args_node {
                for keyword in named(arguments).into_iter().filter(|a| a.kind() == "keyword_argument") {
                    let kname = keyword.child_by_field_name("name").map(|n| self.text(n)).unwrap_or("");
                    if let Some(value) = keyword.child_by_field_name("value") {
                        all_arg_nodes.push(value);
                        if let Some((pname, _, _)) = specs.iter().find(|(n, _, var)| !*var && *n == kname) {
                            supplied.insert(*pname);
                            call_arg_bindings.push(((callee_name.to_owned(), *pname), caller_owner.clone(), value));
                        }
                    }
                }
            }
            for (pname, has_default) in &non_var {
                if !supplied.contains(pname) && !*has_default {
                    self.env.entry((callee_name.to_owned(), *pname)).or_default().opaque = true;
                }
            }
            candidate_direct_calls.push((call.start_byte(), callee_name, caller_owner, all_arg_nodes));
        }
        for s in &splat_called {
            for (pname, _, _) in prep.functions.get(s).into_iter().flatten() {
                self.env.entry(((*s).to_owned(), *pname)).or_default().opaque = true;
            }
        }

        // Seed every bound variable and own parameter before the fixpoint.
        for (key, _, _) in &prep.bindings {
            self.env.entry(key.clone()).or_default();
        }
        for (key, _, _) in &call_arg_bindings {
            self.env.entry(key.clone()).or_default();
        }
        for key in &self.own_params {
            self.env.entry(key.clone()).or_default().own_param = true;
        }
        for _ in 0..PASSES {
            let mut grew = false;
            for (key, expr_owner, value) in &prep.bindings {
                let reach = self.reach_in(expr_owner, *value, 0);
                grew |= self.env.entry(key.clone()).or_default().merge(reach);
            }
            for (key, caller_owner, value) in &call_arg_bindings {
                let mut reach = self.reach_in(caller_owner, *value, 0);
                // Forwarding `caller_owner`'s own parameter wires `caller_ext -> callee_ext`;
                // `callee_int` receives the concrete places passed along internal edges.
                reach.own_param = false;
                grew |= self.env.entry(key.clone()).or_default().merge(reach);
            }
            if !grew {
                break;
            }
        }
        for (call_byte, callee_name, caller_owner, arg_nodes) in candidate_direct_calls {
            if !splat_called.contains(callee_name) && caller_owner != callee_name {
                let forwards = arg_nodes.iter().any(|a| self.reach_in(&caller_owner, *a, 0).own_param);
                self.direct_call_sites.insert(call_byte, (caller_owner, callee_name.to_owned(), forwards));
            }
        }

        // What the module offers to the modules that import its names.
        let mut exports = Vec::new();
        for statement in named(root) {
            let assignment = match statement.kind() {
                "expression_statement" => statement.named_child(0).filter(|n| n.kind() == "assignment"),
                _ => None,
            };
            let target = assignment.and_then(|a| a.child_by_field_name("left")).filter(|t| t.kind() == "identifier");
            if let Some(target) = target {
                let name = self.text(target);
                if exports.iter().all(|(seen, _): &(String, Reach)| seen != name) {
                    exports.push((name.to_owned(), self.reach_name_in("", name).into_reach()));
                }
            }
        }
        // A module-level `from x import NAME` passes NAME on to whoever
        // imports it from here.
        for statement in named(root).into_iter().filter(|s| s.kind() == "import_from_statement") {
            for (_, local) in self.imported_names(statement) {
                if let Some(target) = self.aliases.get(local) {
                    if exports.iter().all(|(seen, _)| seen != local) {
                        exports.push((local.to_owned(), R::place(Anchor::Name(target.clone())).into_reach()));
                    }
                }
            }
        }
        self.facts.exports = exports;
    }

    fn lookup_literals(&self, owner: &str, name: &'s str) -> Option<Vec<String>> {
        if !owner.is_empty() && !self.globals_in_owner.contains(&(owner.to_owned(), name)) {
            let local_key = (owner.to_owned(), name);
            if self.env.contains_key(&local_key)
                || self.literals.contains_key(&local_key)
                || self.own_params.contains(&local_key)
                || self.nested_params.contains(&local_key)
            {
                return self.literals.get(&local_key).cloned();
            }
        }
        self.literals.get(&(String::new(), name)).cloned()
    }

    fn reach_name_in(&self, owner: &str, name: &'s str) -> R {
        if name == "__file__" {
            return R::place(Anchor::File);
        }
        if !owner.is_empty() && !self.globals_in_owner.contains(&(owner.to_owned(), name)) {
            let local_key = (owner.to_owned(), name);
            let is_local = self.env.contains_key(&local_key)
                || self.literals.contains_key(&local_key)
                || self.own_params.contains(&local_key)
                || self.nested_params.contains(&local_key);
            if is_local {
                let mut reach = self.env.get(&local_key).cloned().unwrap_or_default();
                if let Some(values) = self.literals.get(&local_key) {
                    for value in values {
                        reach.merge(R::literal(value));
                    }
                }
                if self.own_params.contains(&local_key) {
                    reach.own_param = true;
                }
                if self.nested_params.contains(&local_key) {
                    reach.opaque = true;
                }
                return reach;
            }
        }
        let top_key = (String::new(), name);
        let mut reach = self.env.get(&top_key).cloned().unwrap_or_default();
        let mut known = self.env.contains_key(&top_key);
        if let Some(values) = self.literals.get(&top_key) {
            for value in values {
                reach.merge(R::literal(value));
            }
            known = true;
        }
        if let Some(target) = self.aliases.get(name) {
            reach.merge(R::place(Anchor::Name(target.clone())));
            known = true;
        }
        if !known {
            reach.opaque = true;
        }
        reach
    }

    /// `base` followed by one more path segment.
    fn extend_in(&self, owner: &str, base: R, segment: Node, depth: usize) -> R {
        let values = match segment.kind() {
            "identifier" => self.lookup_literals(owner, self.text(segment)),
            "conditional_expression" => self.string_values(segment),
            _ => self.string_values(segment).filter(|v| v.len() == 1),
        };
        match values {
            Some(values) => {
                let mut out = R { places: Vec::new(), ..base.clone() };
                for value in values {
                    out.merge(R { unknown: false, opaque: false, own_param: false, temp: false, ..base.clone() }.join(&value));
                }
                out
            }
            None => {
                // An absolute segment would replace the base; that it does
                // not is the one thing assumed about an unknown segment
                // whose own value is not a path.
                let _ = depth;
                base.opened()
            }
        }
    }

    fn reach(&self, node: Node, depth: usize) -> R {
        self.reach_in(&self.owner(), node, depth)
    }

    /// What a path expression may name inside `owner`.
    fn reach_in(&self, owner: &str, node: Node, depth: usize) -> R {
        if depth > MAX_PATH_DEPTH {
            return R::opaque();
        }
        match node.kind() {
            "identifier" => self.reach_name_in(owner, self.text(node)),
            "string" | "concatenated_string" => match self.literal(node) {
                Some(text) => R::literal(&text),
                None => self.reach_fstring_in(owner, node, depth),
            },
            "parenthesized_expression" | "await" => match node.named_child(0) {
                Some(inner) => self.reach_in(owner, inner, depth + 1),
                None => R::opaque(),
            },
            "binary_operator" => {
                let (Some(left), Some(right)) = (node.child_by_field_name("left"), node.child_by_field_name("right")) else {
                    return R::opaque();
                };
                let base = self.reach_in(owner, left, depth + 1);
                match node.child_by_field_name("operator").map(|o| self.text(o)) {
                    Some("/") => self.extend_in(owner, base, right, depth + 1),
                    // String concatenation: whatever follows is not known.
                    Some("+") => base.opened(),
                    _ if base.rooted() || self.reach_in(owner, right, depth + 1).rooted() => R::unknown(),
                    _ => R::opaque(),
                }
            }
            "conditional_expression" | "boolean_operator" => {
                let parts = named(node);
                let mut out = R::default();
                // `a if c else b` lists `a, c, b`; the condition is not a branch.
                for (index, part) in parts.iter().enumerate() {
                    if node.kind() == "conditional_expression" && index == 1 {
                        continue;
                    }
                    out.merge(self.reach_in(owner, *part, depth + 1));
                }
                out
            }
            "attribute" => {
                let (Some(object), Some(attribute)) = (node.child_by_field_name("object"), node.child_by_field_name("attribute"))
                else {
                    return R::opaque();
                };
                if self.text(attribute) == "parent" {
                    return self.reach_in(owner, object, depth + 1).up(1);
                }
                if let Some(dotted) = self.dotted(node) {
                    let head = dotted.split('.').next().unwrap_or("");
                    if self.aliases.contains_key(head) {
                        let resolved = self.resolve(dotted);
                        if resolved == "os.devnull" {
                            return R::default();
                        }
                        return R::place(Anchor::Name(resolved));
                    }
                }
                let inner = self.reach_in(owner, object, depth + 1);
                match (inner.rooted(), inner.temp) {
                    (true, _) => R::unknown(),
                    (false, true) => R::temp(),
                    _ => R::opaque(),
                }
            }
            "subscript" => {
                let Some(value) = node.child_by_field_name("value") else { return R::opaque() };
                let parents = value.kind() == "attribute"
                    && value.child_by_field_name("attribute").is_some_and(|a| self.text(a) == "parents");
                if let (true, Some(object)) = (parents, value.child_by_field_name("object")) {
                    let inner = self.reach_in(owner, object, depth + 1);
                    let index = node.child_by_field_name("subscript").filter(|s| s.kind() == "integer");
                    return match index.and_then(|i| self.text(i).parse::<usize>().ok()) {
                        Some(levels) => inner.up(levels + 1),
                        None if inner.rooted() => R::unknown(),
                        None => inner,
                    };
                }
                let inner = self.reach_in(owner, value, depth + 1);
                match (inner.rooted(), inner.temp) {
                    (true, _) => R::unknown(),
                    (false, true) => R::temp(),
                    _ => R::opaque(),
                }
            }
            "call" => self.reach_call_in(owner, node, depth),
            _ => R::opaque(),
        }
    }

    /// An f-string: its literal start, then something unknown.
    fn reach_fstring_in(&self, owner: &str, node: Node, depth: usize) -> R {
        let mut cursor = node.walk();
        for part in node.children(&mut cursor) {
            match part.kind() {
                "string_content" => {
                    let literal = self.text(part);
                    let directory = literal.rfind('/').map(|cut| &literal[..cut]).unwrap_or("");
                    return if literal.starts_with('/') { R::default() } else { R::literal(directory).opened() };
                }
                "interpolation" => {
                    return match part.child_by_field_name("expression").or_else(|| part.named_child(0)) {
                        Some(expression) => self.reach_in(owner, expression, depth + 1).opened(),
                        None => R::opaque(),
                    };
                }
                _ => {}
            }
        }
        R::opaque()
    }

    fn reach_call_in(&self, owner: &str, node: Node, depth: usize) -> R {
        let Some(function) = node.child_by_field_name("function") else { return R::opaque() };
        let arguments = positional(node);
        let receiver = (function.kind() == "attribute").then(|| function.child_by_field_name("object")).flatten();
        let full = self.dotted(function).map(|name| self.resolve(name));
        let last = match function.kind() {
            "attribute" => function.child_by_field_name("attribute").map(|a| self.text(a)).unwrap_or(""),
            _ => full.as_deref().and_then(|n| n.rsplit('.').next()).unwrap_or(""),
        };
        let first = |this: &Self| arguments.first().map(|a| this.reach_in(owner, *a, depth + 1)).unwrap_or_else(R::opaque);
        // A path made of each argument in turn: `join(a, b, c)`, `Path(a, b)`.
        let joined =
            |this: &Self, base: R, rest: &[Node]| rest.iter().fold(base, |acc, seg| this.extend_in(owner, acc, *seg, depth + 1));

        if let Some(name) = full.as_deref() {
            if name.starts_with("tempfile.") {
                return R::temp();
            }
            match name {
                "os.getcwd" | "os.getcwdb" | "pathlib.Path.cwd" => return R::place(Anchor::Root),
                "os.path.join"
                | "posixpath.join"
                | "pathlib.Path"
                | "pathlib.PurePath"
                | "pathlib.PosixPath"
                | "pathlib.PurePosixPath" => {
                    return match arguments.split_first() {
                        Some((head, rest)) => joined(self, self.reach_in(owner, *head, depth + 1), rest),
                        // `Path()` is the working directory.
                        None if name.starts_with("pathlib.") => R::place(Anchor::Root),
                        None => R::opaque(),
                    };
                }
                "os.path.dirname" | "posixpath.dirname" => return first(self).up(1),
                "os.path.abspath" | "os.path.realpath" | "os.path.normpath" | "os.path.expanduser" | "os.fspath"
                | "os.fsdecode" | "str" => return first(self),
                "glob.glob" | "glob.iglob" | "os.scandir" | "sorted" | "list" | "tuple" | "set" | "reversed" | "iter" => {
                    // The members of a rooted collection lie below it.
                    let inner = first(self);
                    return if matches!(name, "glob.glob" | "glob.iglob" | "os.scandir") { inner.opened() } else { inner };
                }
                _ => {}
            }
        }
        if let Some(receiver) = receiver {
            let object = || self.reach_in(owner, receiver, depth + 1);
            match last {
                "resolve" | "absolute" | "expanduser" | "as_posix" | "__fspath__" => return object(),
                "joinpath" => return joined(self, object(), &arguments),
                "with_name" | "with_suffix" | "with_stem" => return object().up(1).opened(),
                "iterdir" | "glob" | "rglob" | "walk" => return object().opened(),
                _ => {}
            }
        }
        let mut seen = receiver.map(|r| self.reach_in(owner, r, depth + 1)).unwrap_or_default();
        for argument in &arguments {
            seen.merge(self.reach_in(owner, *argument, depth + 1));
        }
        match (seen.rooted(), seen.temp) {
            (true, _) => R::unknown(),
            (false, true) => R::temp(),
            _ => R::opaque(),
        }
    }

    fn children(&mut self, node: Node, depth: usize) {
        for child in named(node) {
            self.visit(child, depth + 1);
        }
    }

    fn visit_field(&mut self, node: Node, field: &str, depth: usize) {
        if let Some(child) = node.child_by_field_name(field) {
            self.visit(child, depth + 1);
        }
    }

    fn is_pure_decorator(&self, expr: Node) -> bool {
        let callee = match expr.kind() {
            "call" => expr.child_by_field_name("function"),
            _ => Some(expr),
        };
        let Some(raw) = callee.and_then(|c| self.dotted(c)) else { return false };
        let head = raw.split('.').next().unwrap_or("");
        if self.non_import_top.contains(head) || self.rebound_names.contains(head) {
            return false;
        }
        if !self.aliases.contains_key(head) {
            return matches!(raw.as_str(), "staticmethod" | "classmethod" | "property");
        }
        let resolved = self.resolve(raw);
        matches!(
            resolved.as_str(),
            "dataclasses.dataclass"
                | "functools.lru_cache"
                | "functools.cache"
                | "functools.cached_property"
                | "functools.wraps"
                | "contextlib.contextmanager"
                | "contextlib.asynccontextmanager"
                | "abc.abstractmethod"
                | "typing.overload"
                | "typing.final"
                | "unittest.skip"
                | "unittest.skipIf"
                | "unittest.skipUnless"
                | "unittest.expectedFailure"
        )
    }

    fn record_use(&mut self, raw: &str, call: bool, no_arg_call: bool, passive_owner: Option<&str>) {
        let cur = self.owner();
        let eff = if call { cur.as_str() } else { passive_owner.unwrap_or(cur.as_str()) };
        let head = raw.split('.').next().unwrap_or("");
        let resolved = self.resolve(raw.to_owned());
        if call {
            self.scoped_calls.insert((cur.clone(), resolved.clone()));
            let dynamic_scope = matches!(
                resolved.as_str(),
                "globals" | "builtins.globals" | "eval" | "builtins.eval" | "exec" | "builtins.exec" | "execfile"
            ) || (matches!(resolved.as_str(), "vars" | "builtins.vars") && no_arg_call)
                || (matches!(resolved.as_str(), "locals" | "builtins.locals") && cur.is_empty());
            if dynamic_scope {
                self.symbol_deps.insert((cur.clone(), "*".to_owned()));
            }
            if head == "self" {
                if let Some(cls) = cur.strip_suffix(".__init__") {
                    self.symbol_deps.insert((cur.clone(), cls.to_owned()));
                }
            }
        }
        if !head.is_empty() {
            if self.non_import_top.contains(head) && eff != head {
                self.symbol_deps.insert((eff.to_owned(), head.to_owned()));
            }
            if self.aliases.contains_key(head) {
                self.external_refs.insert(ScopedRef {
                    owner: eff.to_owned(),
                    head: head.to_owned(),
                    dotted: raw.to_owned(),
                    call,
                });
            }
        }
    }

    fn visit_lhs(&mut self, node: Node, depth: usize) {
        if depth > MAX_DEPTH {
            self.facts.truncated = true;
            return;
        }
        match node.kind() {
            "identifier" => {}
            "pattern_list"
            | "tuple_pattern"
            | "list_pattern"
            | "tuple"
            | "list"
            | "parenthesized_expression"
            | "list_splat_pattern" => {
                for child in named(node) {
                    self.visit_lhs(child, depth + 1);
                }
            }
            _ => self.visit(node, depth),
        }
    }

    /// Walk a top-level constant where passive value
    /// references (`X = fn`, `X = {k: fn}`) attach to
    /// `target` rather than executing eagerly on module import. Any active
    /// subexpression (`call`, operator, dict key, comprehension, keyword arg)
    /// falls back immediately to active `visit`.
    fn visit_passive(&mut self, target: &str, node: Node, depth: usize) {
        if depth > MAX_DEPTH {
            self.facts.truncated = true;
            return;
        }
        match node.kind() {
            "identifier" => self.reference_under(node, self.text(node).to_owned(), Some(target)),
            // Attribute lookup can run descriptors or module/object __getattr__.
            "attribute" => self.visit(node, depth),
            "tuple" | "list" | "parenthesized_expression" => {
                for child in named(node) {
                    self.visit_passive(target, child, depth + 1);
                }
            }
            "dictionary" => {
                for child in named(node) {
                    if child.kind() == "pair" {
                        self.visit_field(child, "key", depth + 1);
                        if let Some(val) = child.child_by_field_name("value") {
                            self.visit_passive(target, val, depth + 1);
                        }
                    } else {
                        self.visit(child, depth + 1);
                    }
                }
            }
            "call"
                if self.fn_depth == 0
                    && self.scope.is_empty()
                    && node
                        .child_by_field_name("function")
                        .filter(|f| f.kind() == "identifier")
                        .is_some_and(|f| self.plain_classes.contains(self.text(f))) =>
            {
                let cls = self.text(node.child_by_field_name("function").expect("checked")).to_owned();
                self.note(cls.clone(), true, line_of(node));
                self.scoped_calls.insert((String::new(), cls.clone()));
                self.symbol_deps.insert((String::new(), format!("{cls}.__init__")));
                if target != cls {
                    self.symbol_deps.insert((target.to_owned(), cls));
                }
                self.visit_field(node, "arguments", depth + 1);
            }
            "lambda" if self.fn_depth == 0 && self.scope.is_empty() => {
                self.visit_field(node, "parameters", depth + 1);
                // Visit lambda body under `target` by recording through a synthetic scope.
                // Lookup the target identifier slice in `self.src` via the parent assignment.
                if let Some(assign) = node.parent().filter(|p| p.kind() == "assignment") {
                    if let Some(left) = assign.child_by_field_name("left").filter(|l| l.kind() == "identifier") {
                        self.scope.push(self.text(left));
                        self.fn_depth += 1;
                        self.visit_field(node, "body", depth + 1);
                        self.fn_depth -= 1;
                        self.scope.pop();
                        return;
                    }
                }
                self.visit(node, depth);
            }
            _ => self.visit(node, depth),
        }
    }

    fn visit(&mut self, node: Node, depth: usize) {
        if depth > MAX_DEPTH {
            self.facts.truncated = true;
            return;
        }
        match node.kind() {
            "comment" | "future_import_statement" => {}
            "import_statement" => self.import(node),
            "import_from_statement" => self.import_from(node),
            "decorated_definition" => {
                let mut non_pure = false;
                let mut def_node = None;
                for child in named(node) {
                    if child.kind() == "decorator" {
                        if !child.named_child(0).is_some_and(|expr| self.is_pure_decorator(expr)) {
                            non_pure = true;
                        }
                        self.visit(child, depth + 1);
                    } else {
                        def_node = Some(child);
                    }
                }
                if let Some(def_node) = def_node {
                    if non_pure && self.fn_depth == 0 {
                        if let Some(target) = def_node.child_by_field_name("name").map(|n| self.text(n)).filter(|n| !n.is_empty())
                        {
                            // A custom decorator receives the function/class at definition time
                            // and may invoke or register it globally.
                            let target_top = self.scope.first().copied().unwrap_or(target);
                            self.symbol_deps.insert((self.owner(), target_top.to_owned()));
                        }
                    }
                    self.visit(def_node, depth + 1);
                }
            }
            "function_definition" => self.function(node, depth),
            "class_definition" => {
                let name = node.child_by_field_name("name").map(|n| self.text(n)).unwrap_or("");
                self.visit_field(node, "type_parameters", depth);
                if let Some(supers) = node.child_by_field_name("superclasses") {
                    if self.fn_depth == 0 && self.scope.is_empty() && !name.is_empty() {
                        for arg in named(supers) {
                            if arg.kind() == "keyword_argument" {
                                self.visit(arg, depth + 1);
                            } else {
                                if self.dotted(arg).as_deref() == Some("type") && !self.aliases.contains_key("type") {
                                    self.symbol_deps.insert((String::new(), name.to_owned()));
                                }
                                // Constructing a subclass invokes metaclass / __init_subclass__ hooks.
                                self.visit(arg, depth + 1);
                            }
                        }
                    } else {
                        self.visit(supers, depth + 1);
                    }
                }
                self.scope.push(name);
                self.visit_field(node, "body", depth);
                self.scope.pop();
            }
            "parameters" | "lambda_parameters" => self.parameters(node, depth),
            "while_statement" | "for_statement" => {
                let info = self.loop_info(node);
                self.loops.push(info);
                self.children(node, depth);
                self.loops.pop();
            }
            "except_clause" => {
                let alias = node.child_by_field_name("alias").or_else(|| {
                    named(node).into_iter().find(|c| c.kind() == "as_pattern").and_then(|p| p.child_by_field_name("alias"))
                });
                self.caught.push(alias.map(|a| self.text(a)).unwrap_or(""));
                self.children(node, depth);
                self.caught.pop();
            }
            "assignment" => {
                self.assignment(node);
                let left = node.child_by_field_name("left");
                let right = node.child_by_field_name("right");
                if let Some(left) = left {
                    self.visit_lhs(left, depth + 1);
                }
                self.visit_field(node, "type", depth);
                if let Some(right) = right {
                    let top_ident = (self.fn_depth == 0 && self.scope.is_empty())
                        .then(|| left.filter(|l| l.kind() == "identifier").map(|l| self.text(l)).filter(|n| !n.is_empty()))
                        .flatten();
                    match top_ident {
                        Some(target) => self.visit_passive(target, right, depth + 1),
                        None => self.visit(right, depth + 1),
                    }
                }
            }
            "subscript" => {
                if let (Some(val), Some(sub)) = (node.child_by_field_name("value"), node.child_by_field_name("subscript")) {
                    if self.dotted(val).map(|d| self.resolve(d)).as_deref() == Some("sys.modules")
                        && self.text(sub).contains("__name__")
                    {
                        self.symbol_deps.insert((self.owner(), "*".to_owned()));
                    }
                }
                self.children(node, depth);
            }
            "call" => self.call(node, depth),
            "attribute" => match self.dotted(node) {
                Some(name) => self.reference(node, name),
                None => self.visit_field(node, "object", depth),
            },
            "identifier" => self.reference(node, self.text(node).to_owned()),
            "keyword_argument" => self.visit_field(node, "value", depth),
            "expression_statement" if is_string_statement(node) => {}
            "string" | "concatenated_string" => self.string(node, depth),
            _ => self.children(node, depth),
        }
    }

    /// A non-call reference. Only names that lead back to an import are
    /// recorded in `facts.symbols`; intra-module top-level references are
    /// recorded in `symbol_deps`.
    fn reference(&mut self, node: Node, name: String) {
        self.reference_under(node, name, None);
    }

    fn reference_under(&mut self, node: Node, name: String, passive_owner: Option<&str>) {
        if name == "self" {
            let cur = self.owner();
            if let Some(cls) = cur.strip_suffix(".__init__") {
                // Escaping `self` may expose every method, even through an apparent
                // WeakSet: that binding can be replaced or have custom hash behavior.
                let cls = cls.to_owned();
                self.symbol_deps.insert((cur, cls));
            }
        }
        self.record_use(&name, false, false, passive_owner);
        if !self.aliases.contains_key(name.split('.').next().unwrap_or("")) {
            return;
        }
        let name = self.resolve(name);
        if name == "sys.executable" {
            let site = self.site(node, "sys.executable");
            self.facts.sys_executable.push(site);
        }
        self.note(name, false, line_of(node));
    }

    fn dynamic(&mut self, node: Node, what: impl Into<String>, prefix: Option<String>) {
        let load = DynamicLoad { line: line_of(node), func: self.func(), owner: self.owner(), what: what.into(), prefix };
        self.facts.dynamic_loads.push(load);
    }

    fn import(&mut self, node: Node) {
        let owner = self.owner();
        for child in named(node) {
            let (module, bound) = match child.kind() {
                "dotted_name" => {
                    let m = self.text(child);
                    (m, m.split('.').next().unwrap_or(""))
                }
                "aliased_import" => match (child.child_by_field_name("name"), child.child_by_field_name("alias")) {
                    (Some(name), Some(alias)) => (self.text(name), self.text(alias)),
                    (Some(name), None) => {
                        let m = self.text(name);
                        (m, m.split('.').next().unwrap_or(""))
                    }
                    _ => continue,
                },
                _ => continue,
            };
            let bindings = if bound.is_empty() { Vec::new() } else { vec![(String::new(), bound.to_owned())] };
            self.facts.imports.push(Import {
                module: module.to_owned(),
                level: 0,
                names: Vec::new(),
                owner: owner.clone(),
                bindings,
                line: line_of(node),
            });
        }
    }

    fn import_from(&mut self, node: Node) {
        let (level, module) = self.import_source(node);
        let pairs = self.imported_names(node);
        let mut names: Vec<String> = pairs.iter().map(|(name, _)| (*name).to_owned()).collect();
        let mut bindings: Vec<(String, String)> =
            pairs.into_iter().filter(|(n, _)| !n.is_empty()).map(|(n, l)| (n.to_owned(), l.to_owned())).collect();
        if named(node).into_iter().any(|c| c.kind() == "wildcard_import") {
            names.push("*".to_owned());
            bindings.push(("*".to_owned(), "*".to_owned()));
            if level == 0 && SENSITIVE_WILDCARDS.contains(&module) {
                // Every name of the module is now callable bare, so a loader
                // or a scan can no longer be recognised by its name.
                self.dynamic(node, format!("wildcard import of {module}"), None);
            }
        }
        self.facts.imports.push(Import {
            module: module.to_owned(),
            level,
            names,
            owner: self.owner(),
            bindings,
            line: line_of(node),
        });
    }

    fn function(&mut self, node: Node, depth: usize) {
        let fn_name = node.child_by_field_name("name").map(|n| self.text(n)).unwrap_or("");
        if self.fn_depth == 0 {
            if self.scope.is_empty() && matches!(fn_name, "__getattr__" | "__dir__") {
                self.symbol_deps.insert((String::new(), fn_name.to_owned()));
            } else if self.scope.len() == 1 && fn_name == "__init_subclass__" {
                self.symbol_deps.insert((String::new(), self.scope[0].to_owned()));
            }
        }
        // Parameter defaults and annotations run when `def` executes, in the
        // enclosing scope rather than inside the deferred function body.
        self.visit_field(node, "type_parameters", depth);
        self.visit_field(node, "parameters", depth);
        self.visit_field(node, "return_type", depth);

        self.scope.push(fn_name);
        if let Some(body) = node.child_by_field_name("body") {
            let (body_hash, statements) = hash_body(body, self.src);
            self.facts.functions.push(FunctionFact { name: self.func(), line: line_of(node), body_hash, statements });
        }
        // A nested function is not "inside" the loop or handler that defines it.
        let loops = std::mem::take(&mut self.loops);
        let caught = std::mem::take(&mut self.caught);
        self.fn_depth += 1;
        self.visit_field(node, "body", depth);
        self.fn_depth -= 1;
        self.loops = loops;
        self.caught = caught;
        self.scope.pop();
    }

    /// Parameter names are bindings, not references; defaults and
    /// annotations are expressions.
    fn parameters(&mut self, node: Node, depth: usize) {
        for parameter in named(node) {
            self.visit_field(parameter, "value", depth);
            self.visit_field(parameter, "type", depth);
        }
    }

    fn loop_info(&self, node: Node) -> Loop {
        let text = self.text(node);
        Loop {
            sleeps: text.contains("sleep("),
            bounded: node.kind() == "for_statement" || BOUND_HINTS.iter().any(|h| text.contains(h)),
        }
    }

    fn assignment(&mut self, node: Node) {
        let (Some(left), Some(right)) = (node.child_by_field_name("left"), node.child_by_field_name("right")) else {
            return;
        };
        let stores_caught = right.kind() == "identifier" && self.caught.contains(&self.text(right));
        let on_self = left.kind() == "attribute"
            && left.child_by_field_name("object").is_some_and(|o| o.kind() == "identifier" && self.text(o) == "self");
        if stores_caught && on_self {
            let site = self.site(node, format!("{} = {}", self.text(left), self.text(right)));
            self.facts.exc_on_self.push(site);
        }
        // `sys.path = […]` redirects every later import.
        if self.dotted(left).map(|name| self.resolve(name)).as_deref() == Some("sys.path") {
            self.dynamic(node, "sys.path assignment", None);
        }
    }

    /// The value of a string literal with no interpolation, with escapes
    /// decoded as Python decodes them (`"lib\x2esecret"` is `lib.secret`).
    fn literal(&self, node: Node) -> Option<String> {
        match node.kind() {
            "string" => {
                let mut cursor = node.walk();
                let (mut prefix, mut start, mut end) = ("", node.start_byte(), node.end_byte());
                for part in node.children(&mut cursor) {
                    match part.kind() {
                        "string_start" => {
                            prefix = self.text(part).trim_end_matches(['"', '\'']);
                            start = part.end_byte();
                        }
                        "string_end" => end = part.start_byte(),
                        "interpolation" => return None,
                        _ => {}
                    }
                }
                let Ok(raw) = std::str::from_utf8(self.src.get(start..end)?) else {
                    self.bad_text.set(true);
                    return None;
                };
                if prefix.contains(['r', 'R']) {
                    Some(raw.to_owned())
                } else {
                    unescape(raw)
                }
            }
            "concatenated_string" => {
                let mut out = String::new();
                for part in named(node) {
                    if part.kind() != "comment" {
                        out.push_str(&self.literal(part)?);
                    }
                }
                Some(out)
            }
            _ => None,
        }
    }

    fn string(&mut self, node: Node, depth: usize) {
        if let Some(value) = self.literal(node) {
            let heads_argv = node.parent().is_some_and(|p| {
                matches!(p.kind(), "list" | "tuple") && p.named_child(0).is_some_and(|first| first.id() == node.id())
            });
            if (value == "python" && heads_argv) || is_bare_python_command(&value) {
                let site = self.site(node, value.clone());
                self.facts.bare_python.push(site);
            }
            return;
        }
        // An f-string: its interpolations are expressions.
        let mut stack = vec![node];
        while let Some(current) = stack.pop() {
            for part in named(current) {
                match part.kind() {
                    "interpolation" => self.children(part, depth),
                    "string" => stack.push(part),
                    _ => {}
                }
            }
        }
    }

    /// As much of a string-valued expression as the source spells out, and
    /// whether that is all of it. `__name__` and `__package__` are written
    /// `@module` and `@package`.
    fn static_text(&self, node: Node) -> (String, bool) {
        match node.kind() {
            "identifier" if self.text(node) == "__name__" => ("@module".to_owned(), true),
            "identifier" if self.text(node) == "__package__" => ("@package".to_owned(), true),
            "string" | "concatenated_string" => match self.literal(node) {
                Some(text) => (text, true),
                None => {
                    let mut out = String::new();
                    let mut cursor = node.walk();
                    for part in node.children(&mut cursor) {
                        match part.kind() {
                            "string_content" => out.push_str(self.text(part)),
                            "interpolation" => {
                                let inner = part.child_by_field_name("expression").or_else(|| part.named_child(0));
                                match inner.map(|e| self.static_text(e)) {
                                    Some((text, true)) => out.push_str(&text),
                                    _ => return (out, false),
                                }
                            }
                            _ => {}
                        }
                    }
                    (out, true)
                }
            },
            "parenthesized_expression" => match node.named_child(0) {
                Some(inner) => self.static_text(inner),
                None => (String::new(), false),
            },
            "binary_operator" if node.child_by_field_name("operator").map(|o| self.text(o)) == Some("+") => {
                let (Some(left), Some(right)) = (node.child_by_field_name("left"), node.child_by_field_name("right")) else {
                    return (String::new(), false);
                };
                match self.static_text(left) {
                    (mut text, true) => {
                        let (rest, whole) = self.static_text(right);
                        text.push_str(&rest);
                        (text, whole)
                    }
                    partial => partial,
                }
            }
            _ => (String::new(), false),
        }
    }

    /// The module-name prefix a computed import shows: up to its last dot.
    fn module_prefix(&self, node: Node) -> Option<String> {
        let (text, whole) = self.static_text(node);
        let prefix = if whole { text } else { text[..text.rfind('.')? + 1].to_owned() };
        (!prefix.is_empty() && !prefix.starts_with('.')).then_some(prefix)
    }

    fn read(&mut self, node: Node, what: &str, shape: ReadShape, target: R) {
        if target.is_nothing() {
            return;
        }
        let owner = self.owner();
        let internal_clean = !owner.is_empty() && !target.opaque && target.own_param;
        let site = ReadSite {
            line: line_of(node),
            func: self.func(),
            owner,
            what: what.to_owned(),
            shape,
            reach: target.into_reach(),
            internal_clean,
        };
        self.facts.reads.push(site);
    }

    /// A child process. A Python child with a literal script or module is an
    /// edge to that code; anything else can read whatever it is shown.
    fn process(&mut self, node: Node, what: &str, arguments: &[Node]) {
        let argv = arguments.first().filter(|a| matches!(a.kind(), "list" | "tuple")).map(|a| named(*a)).unwrap_or_default();
        let is_python = argv.first().is_some_and(|head| {
            self.dotted(*head).map(|name| self.resolve(name)).as_deref() == Some("sys.executable")
                || matches!(self.literal(*head).as_deref(), Some("python" | "python3"))
        });
        if arguments.first().is_some_and(|a| self.string_values(*a).is_some_and(|v| v.iter().any(|s| s == "ls-files")))
            || argv.iter().any(|a| self.literal(*a).as_deref() == Some("ls-files"))
        {
            // `git ls-files` lists the tree.
            self.read(node, "git ls-files", ReadShape::Subtree, R::place(Anchor::Root));
        }
        if is_python {
            let flag = argv.get(1).and_then(|a| self.literal(*a));
            match (flag.as_deref(), argv.get(1), argv.get(2).and_then(|a| self.literal(*a))) {
                (Some("-m"), _, Some(module)) => {
                    self.facts.imports.push(Import {
                        module,
                        level: 0,
                        names: Vec::new(),
                        owner: self.owner(),
                        bindings: Vec::new(),
                        line: line_of(node),
                    });
                    return;
                }
                (Some(flag), _, _) if flag.starts_with('-') => {}
                (_, Some(script), _) => {
                    let target = self.reach(*script, 0);
                    if target.rooted() {
                        self.read(node, "python child script", ReadShape::Module, target);
                        return;
                    }
                }
                _ => {}
            }
        }
        self.read(node, what, ReadShape::Process, R::opaque());
    }

    fn call(&mut self, node: Node, depth: usize) {
        let Some(function) = node.child_by_field_name("function") else {
            return self.children(node, depth);
        };
        let arguments = node.child_by_field_name("arguments");
        let raw_dotted = self.dotted(function);
        let full = raw_dotted.clone().map(|name| self.resolve(name));
        let method = function.kind() == "attribute";
        let receiver = method.then(|| function.child_by_field_name("object")).flatten();
        let last: String = match &full {
            Some(name) => name.rsplit('.').next().unwrap_or("").to_owned(),
            None if method => function.child_by_field_name("attribute").map(|a| self.text(a)).unwrap_or("").to_owned(),
            None => String::new(),
        };
        let name = full.as_deref().unwrap_or("");
        let positional = positional(node);
        let keyword = |this: &Self, wanted: &str| {
            arguments.into_iter().flat_map(named).filter(|a| a.kind() == "keyword_argument").find_map(|k| {
                (k.child_by_field_name("name").map(|n| this.text(n)) == Some(wanted))
                    .then(|| k.child_by_field_name("value"))
                    .flatten()
            })
        };
        let first_literal = positional.first().and_then(|a| self.literal(*a));
        let arguments_text = arguments.map(|a| self.text(a)).unwrap_or("");
        // The path a call reads: its nth argument, or nothing known at all.
        let argument = |this: &Self, index: usize| positional.get(index).map(|a| this.reach(*a, 0)).unwrap_or_else(R::opaque);
        let of_receiver = |this: &Self| receiver.map(|r| this.reach(r, 0)).unwrap_or_else(R::opaque);

        match name {
            "importlib.import_module" | "__import__" | "importlib.__import__" => {
                let anchored = positional.get(1).or(keyword(self, "package").as_ref()).copied();
                let own_package = anchored.is_none_or(|a| self.text(a) == "__package__");
                let fromlist =
                    keyword(self, "fromlist").or(positional.get(3).copied()).filter(|_| name != "importlib.import_module");
                let names = match fromlist.map(|f| (self.string_values(f), f.kind())) {
                    None => Some(Vec::new()),
                    Some((Some(names), _)) => Some(names),
                    Some((None, "tuple" | "list")) if fromlist.is_some_and(|f| f.named_child_count() == 0) => Some(Vec::new()),
                    Some(_) => None,
                };
                match (&first_literal, names) {
                    (Some(target), Some(names)) if own_package || !target.starts_with('.') => {
                        let level = target.bytes().take_while(|b| *b == b'.').count();
                        self.facts.imports.push(Import {
                            module: target[level..].to_owned(),
                            level: level.min(255) as u8,
                            names,
                            owner: self.owner(),
                            bindings: Vec::new(),
                            line: line_of(node),
                        });
                    }
                    _ => {
                        let prefix = positional.first().and_then(|a| self.module_prefix(*a));
                        self.dynamic(node, name, prefix);
                    }
                }
            }
            "runpy.run_module" => match &first_literal {
                Some(module) => self.facts.imports.push(Import {
                    module: module.clone(),
                    level: 0,
                    names: Vec::new(),
                    owner: self.owner(),
                    bindings: Vec::new(),
                    line: line_of(node),
                }),
                None => {
                    let prefix = positional.first().and_then(|a| self.module_prefix(*a));
                    self.dynamic(node, name, prefix);
                }
            },
            "imp.load_module"
            | "pkgutil.iter_modules"
            | "pkgutil.walk_packages"
            | "exec"
            | "eval"
            | "execfile"
            | "importlib.reload"
            | "sys.path.insert"
            | "sys.path.append"
            | "sys.path.extend"
            | "site.addsitedir" => self.dynamic(node, name, None),
            "runpy.run_path" => self.read(node, name, ReadShape::Module, argument(self, 0)),
            "importlib.util.spec_from_file_location" | "importlib.machinery.SourceFileLoader" | "imp.load_source" => {
                let target = match keyword(self, "location").or(keyword(self, "path")) {
                    Some(value) => self.reach(value, 0),
                    None => argument(self, 1),
                };
                self.read(node, name, ReadShape::Module, target)
            }
            "open" | "io.open" | "codecs.open" | "os.open" | "tokenize.open" | "zipfile.ZipFile" | "tarfile.open"
            | "shutil.copy" | "shutil.copy2" | "shutil.copyfile" | "shutil.move" => {
                self.read(node, name, ReadShape::File, argument(self, 0))
            }
            "os.stat" | "os.lstat" | "os.access" | "os.readlink" | "os.path.exists" | "os.path.lexists" | "os.path.isfile"
            | "os.path.isdir" | "os.path.islink" | "os.path.getsize" | "os.path.getmtime" => {
                self.read(node, name, ReadShape::Probe, argument(self, 0))
            }
            "shutil.copytree" | "os.walk" | "os.fwalk" => self.read(node, name, ReadShape::Subtree, argument(self, 0)),
            "os.listdir" | "os.scandir" => {
                let target = if positional.is_empty() { R::place(Anchor::Root) } else { argument(self, 0) };
                self.read(node, name, ReadShape::Level, target)
            }
            "glob.glob" | "glob.iglob" => self.read(node, name, ReadShape::Pattern, argument(self, 0)),
            "subprocess.run"
            | "subprocess.call"
            | "subprocess.check_call"
            | "subprocess.check_output"
            | "subprocess.Popen"
            | "subprocess.getoutput"
            | "subprocess.getstatusoutput"
            | "os.system"
            | "os.popen"
            | "os.posix_spawn"
            | "os.posix_spawnp" => self.process(node, name, &positional),
            _ if name.starts_with("os.exec") || name.starts_with("os.spawn") => self.process(node, name, &positional),
            "os.replace" | "os.rename" => {
                let site = self.site(node, name);
                self.facts.replaces.push(site);
            }
            _ if method => {
                let what = format!(".{last}");
                match last.as_str() {
                    "read_text" | "read_bytes" | "open" => self.read(node, &what, ReadShape::File, of_receiver(self)),
                    "exists" | "is_file" | "is_dir" | "is_symlink" | "stat" | "lstat" | "samefile" | "readlink" => {
                        self.read(node, &what, ReadShape::Probe, of_receiver(self))
                    }
                    "iterdir" => self.read(node, &what, ReadShape::Level, of_receiver(self)),
                    "walk" => self.read(node, &what, ReadShape::Subtree, of_receiver(self)),
                    "glob" | "rglob" => {
                        let patterns = positional.first().and_then(|a| match a.kind() {
                            "identifier" => self.lookup_literals(&self.owner(), self.text(*a)),
                            _ => self.string_values(*a),
                        });
                        let target = of_receiver(self);
                        match (patterns, last.as_str()) {
                            (Some(patterns), "glob") => self.read(node, &what, ReadShape::Glob(patterns), target),
                            (Some(patterns), _) => self.read(node, &what, ReadShape::RGlob(patterns), target),
                            // A pattern built at run time: anything below.
                            (None, _) => self.read(node, &what, ReadShape::Subtree, target.opened()),
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        if matches!(last.as_str(), "flock" | "lockf") {
            let sleeping: Vec<&Loop> = self.loops.iter().filter(|l| l.sleeps).collect();
            self.facts.flocks.push(FlockSite {
                line: line_of(node),
                func: self.func(),
                call: if name.is_empty() { format!(".{last}") } else { name.to_owned() },
                nonblocking: arguments_text.contains("LOCK_NB"),
                unlock: arguments_text.contains("LOCK_UN"),
                flags_opaque: !arguments_text.contains("LOCK_"),
                polled: !sleeping.is_empty(),
                poll_bounded: sleeping.iter().all(|l| l.bounded),
            });
        }
        if matches!(last.as_str(), "strftime" | "strptime") {
            let format = if last == "strptime" {
                positional.get(1).and_then(|a| self.literal(*a))
            } else {
                positional.iter().find_map(|a| self.literal(*a))
            };
            self.facts.strftimes.push(StrftimeSite { line: line_of(node), func: self.func(), format });
        }
        if let Some(key) = first_literal.filter(|k| !last.is_empty() && is_dotted_key(k)) {
            self.facts.settings_reads.push(SettingsRead { line: line_of(node), reader: last.clone(), key });
        }

        if name == "sys.modules.get" && positional.first().is_some_and(|a| self.text(*a) == "__name__") {
            self.symbol_deps.insert((self.owner(), "*".to_owned()));
        }
        if let Some((caller, callee, forwards)) = self.direct_call_sites.get(&node.start_byte()).cloned() {
            let resolved = self.resolve(callee.clone());
            self.scoped_calls.insert((caller.clone(), resolved));
            self.internal_calls.insert((caller, callee, forwards));
        } else if let Some(raw) = &raw_dotted {
            self.record_use(raw, true, positional.is_empty(), None);
        }
        match full {
            Some(name) => self.note(name, true, line_of(node)),
            None => self.visit(function, depth + 1),
        }
        if let Some(arguments) = arguments {
            self.visit(arguments, depth + 1);
        }
    }
}

fn hash_body(body: Node, src: &[u8]) -> (Digest32, u32) {
    let mut hasher = blake3::Hasher::new_derive_key(BODY_HASH_DOMAIN);
    let mut statements = 0u32;
    let mut leading = true;
    let mut cursor = body.walk();
    for statement in body.named_children(&mut cursor) {
        if statement.kind() == "comment" {
            continue;
        }
        if std::mem::take(&mut leading) && is_string_statement(statement) {
            continue;
        }
        statements += 1;
        hash_node(statement, src, &mut hasher, 0);
    }
    (Digest32::from_bytes(*hasher.finalize().as_bytes()), statements)
}

fn hash_node(node: Node, src: &[u8], hasher: &mut blake3::Hasher, depth: usize) {
    if node.kind() == "comment" {
        return;
    }
    hasher.update(node.kind().as_bytes());
    hasher.update(&[0]);
    if node.child_count() == 0 || depth > MAX_DEPTH {
        let text = &src[node.byte_range()];
        hasher.update(&(text.len() as u64).to_le_bytes());
        hasher.update(text);
        return;
    }
    hasher.update(b"(");
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        hash_node(child, src, hasher, depth + 1);
    }
    hasher.update(b")");
}

/// `python -m x`, `python tool.py`, `python ./x`: a command, not prose.
fn is_bare_python_command(text: &str) -> bool {
    let Some(rest) = text.trim_start().strip_prefix("python ") else {
        return false;
    };
    let first = rest.split_whitespace().next().unwrap_or("");
    first.starts_with('-') || first.ends_with(".py") || first.contains('/')
}

fn is_dotted_key(text: &str) -> bool {
    text.len() <= 128
        && text.contains('.')
        && !text.contains("..")
        && !text.starts_with('.')
        && !text.ends_with('.')
        && text.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

const COMMAND_WORDS: [&str; 10] = ["exec", "env", "sudo", "time", "nohup", "then", "do", "else", "xargs", "command"];

/// Whether a recipe line runs `python` in command position.
fn recipe_line_runs_bare_python(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return false;
    }
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    tokens.iter().enumerate().any(|(i, raw)| {
        let opener = |c: char| matches!(c, '"' | '\'' | '(' | '`' | '$' | '@');
        let token = raw.trim_start_matches(opener).trim_end_matches(['"', '\'', ')', '`', ';']);
        if token != "python" {
            return false;
        }
        let quoted_start = raw.starts_with(opener);
        let has_next = i + 1 < tokens.len();
        match i.checked_sub(1).map(|p| tokens[p]) {
            None => true,
            Some(previous) => {
                quoted_start
                    || matches!(previous, "-" | "&&" | "||" | "|" | ";")
                    || previous.ends_with([';', '|', '('])
                    || COMMAND_WORDS.contains(&previous)
                    || (has_next && previous.ends_with([':', '=']))
            }
        }
    })
}

fn extract_recipe(source: &[u8]) -> FileFacts {
    let text = String::from_utf8_lossy(source);
    let mut facts = FileFacts { language: Language::Recipe, ..FileFacts::default() };
    for (index, line) in text.lines().enumerate() {
        if recipe_line_runs_bare_python(line) {
            let what: String = line.trim().chars().take(160).collect();
            facts.bare_python.push(Site { line: index as u32 + 1, func: String::new(), what });
        }
    }
    facts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn py(source: &str) -> FileFacts {
        extract(FileKind::Python, source.as_bytes())
    }

    fn symbol<'a>(facts: &'a FileFacts, name: &str, call: bool) -> Option<&'a SymbolRef> {
        facts.symbols.iter().find(|s| s.name == name && s.call == call)
    }

    /// `(what, shape, places as "anchor^up/tail[+]", unknown, opaque)` per read.
    fn reads(facts: &FileFacts) -> Vec<(String, String, Vec<String>, bool, bool)> {
        facts
            .reads
            .iter()
            .map(|site| {
                let places = site
                    .reach
                    .places
                    .iter()
                    .map(|p| {
                        let anchor = match &p.anchor {
                            Anchor::File => "file".to_owned(),
                            Anchor::Root => "root".to_owned(),
                            Anchor::Name(name) => name.clone(),
                        };
                        format!("{anchor}^{}/{}{}", p.up, p.tail, if p.open { "+" } else { "" })
                    })
                    .collect();
                let shape = format!("{:?}", site.shape);
                (site.what.clone(), shape, places, site.reach.unknown, site.reach.opaque)
            })
            .collect()
    }

    fn read(what: &str, shape: &str, places: &[&str], unknown: bool, opaque: bool) -> (String, String, Vec<String>, bool, bool) {
        (what.to_owned(), shape.to_owned(), places.iter().map(|p| p.to_string()).collect(), unknown, opaque)
    }

    #[test]
    fn imports_in_every_spelling() {
        let facts = py("import os\nimport a.b.c as abc, json\nfrom x.y import z, w as v\nfrom . import sib\n\
                        from ..pkg.mod import thing\nfrom m import *\nfrom __future__ import annotations\n\
                        def f():\n    import late\n");
        let got: Vec<(&str, u8, Vec<&str>)> =
            facts.imports.iter().map(|i| (i.module.as_str(), i.level, i.names.iter().map(String::as_str).collect())).collect();
        assert_eq!(
            got,
            vec![
                ("os", 0, vec![]),
                ("a.b.c", 0, vec![]),
                ("json", 0, vec![]),
                ("x.y", 0, vec!["z", "w"]),
                ("", 1, vec!["sib"]),
                ("pkg.mod", 2, vec!["thing"]),
                ("m", 0, vec!["*"]),
                ("late", 0, vec![]),
            ]
        );
        assert_eq!(facts.imports[7].line, 9);
        assert!(!facts.parse_error && facts.language == Language::Python);
    }

    #[test]
    fn tooth_literal_import_module_is_static_and_computed_is_dynamic() {
        let facts = py("import importlib\nfrom importlib import import_module as im\n\
                        a = importlib.import_module('pkg.plugin')\nb = im(name)\nc = __import__('json')\n\
                        exec(code)\nd = importlib.import_module('.rel', __package__)\n\
                        e = importlib.import_module('.rel', 'other.pkg')\nf = __import__('x', fromlist=['y', 'z'])\n\
                        g = __import__('x', fromlist=names)\n");
        let static_targets: Vec<(&str, u8, usize)> =
            facts.imports.iter().skip(2).map(|i| (i.module.as_str(), i.level, i.names.len())).collect();
        assert_eq!(static_targets, vec![("pkg.plugin", 0, 0), ("json", 0, 0), ("rel", 1, 0), ("x", 0, 2)]);
        let dynamic: Vec<(&str, u32)> = facts.dynamic_loads.iter().map(|s| (s.what.as_str(), s.line)).collect();
        // A relative name anchored anywhere but `__package__`, and a computed fromlist, are dynamic.
        assert_eq!(
            dynamic,
            vec![("importlib.import_module", 4), ("exec", 6), ("importlib.import_module", 8), ("__import__", 10)]
        );
        assert!(py("import importlib\nx = importlib.import_module('a.b')\n").dynamic_loads.is_empty());
    }

    /// Escapes are decoded as Python decodes them, so a module name cannot
    /// be hidden from the import graph behind `\x2e`.
    #[test]
    fn tooth_escaped_literals_mean_what_python_says() {
        let facts = py("import importlib\na = importlib.import_module(\"lib\\x2esecret\")\n\
                        b = importlib.import_module('lib\\u002eother')\nc = importlib.import_module(r'raw\\x2ename')\n\
                        d = setting('land\\x2erun')\ne = importlib.import_module('one' '.two')\n");
        let modules: Vec<&str> = facts.imports.iter().skip(1).map(|i| i.module.as_str()).collect();
        assert_eq!(modules, vec!["lib.secret", "lib.other", "raw\\x2ename", "one.two"]);
        assert_eq!(facts.settings_reads.iter().find(|r| r.reader == "setting").unwrap().key, "land.run");
        assert_eq!(unescape("a\\n\\t\\\\\\x41\\101\\q\\\nz").as_deref(), Some("a\n\t\\AA\\qz"));
        assert_eq!(unescape("\\N{DASH}"), None);
    }

    #[test]
    fn computed_imports_show_their_literal_prefix() {
        let facts = py("import importlib\n\
                        a = importlib.import_module(f'fleetd.hooks.rungs.{name}')\n\
                        b = importlib.import_module('land.checks.' + name)\n\
                        c = importlib.import_module(__name__ + '.' + name)\n\
                        d = importlib.import_module(f'{__package__}.plugins.{name}')\n\
                        e = importlib.import_module(name)\nf = importlib.import_module(prefix + name)\n");
        let prefixes: Vec<Option<&str>> = facts.dynamic_loads.iter().map(|d| d.prefix.as_deref()).collect();
        assert_eq!(
            prefixes,
            vec![Some("fleetd.hooks.rungs."), Some("land.checks."), Some("@module."), Some("@package.plugins."), None, None]
        );
    }

    #[test]
    fn paths_are_followed_from_file_cwd_and_literals() {
        let facts = py("import os, json\nfrom pathlib import Path\n\
                        HERE = Path(__file__).resolve().parent\nREPO = HERE.parent\nDATA = os.path.join(os.path.dirname(__file__), 'data')\n\
                        def load():\n    a = open(REPO / 'fleetd' / 'defaults.json')\n    b = (HERE / 'fixtures' / 'x.json').read_text()\n\
                        \x20   c = json.load(open(os.path.join(DATA, 'table.json')))\n    d = open('relative/from/cwd.txt')\n\
                        \x20   e = open('/etc/hostname')\n    f = Path(__file__).parents[2] / 'top.txt'\n    return f.exists()\n");
        assert_eq!(
            reads(&facts),
            vec![
                read("open", "File", &["file^2/fleetd/defaults.json"], false, false),
                read(".read_text", "File", &["file^1/fixtures/x.json"], false, false),
                read("open", "File", &["file^1/data/table.json"], false, false),
                read("open", "File", &["root^0/relative/from/cwd.txt"], false, false),
                read(".exists", "Probe", &["file^3/top.txt"], false, false),
            ]
        );
        let exported: Vec<&str> = facts.exports.iter().map(|(name, _)| name.as_str()).collect();
        // Module-level path names, then the names it imported with `from`.
        assert_eq!(exported, ["HERE", "REPO", "DATA", "Path"]);
    }

    #[test]
    fn scans_listings_and_globs_carry_their_roots() {
        let facts = py("import os, glob, subprocess, shutil\nfrom pathlib import Path\nREPO = Path(__file__).parent.parent\n\
                        TOPS = ('fleetd', 'fabd')\n\
                        def scan(tmp):\n    for top in TOPS:\n        for _ in os.walk(REPO / top): pass\n\
                        \x20   glob.glob(str(REPO / 'docs' / '*.md'))\n    list((REPO / 'tests').rglob('*.json'))\n\
                        \x20   (REPO / 'land').glob(pattern)\n    subprocess.run(['git', 'ls-files'])\n\
                        \x20   shutil.copytree(REPO / 'fabd', tmp)\n    for p in (REPO / 'bin').iterdir():\n        p.read_text()\n\
                        \x20   return os.listdir(REPO)\n");
        assert_eq!(
            reads(&facts),
            vec![
                read("os.walk", "Subtree", &["file^2/fleetd", "file^2/fabd"], false, false),
                read("glob.glob", "Pattern", &["file^2/docs/*.md"], false, false),
                read(".rglob", "RGlob([\"*.json\"])", &["file^2/tests"], false, false),
                read(".glob", "Subtree", &["file^2/land+"], false, false),
                read("git ls-files", "Subtree", &["root^0/"], false, false),
                read("subprocess.run", "Process", &[], false, true),
                read("shutil.copytree", "Subtree", &["file^2/fabd"], false, false),
                read(".iterdir", "Level", &["file^2/bin"], false, false),
                read(".read_text", "File", &["file^2/bin+"], false, false),
                read("os.listdir", "Level", &["file^2/"], false, false),
            ]
        );
        assert_eq!(facts.scans().count(), 8);
    }

    /// What the analysis cannot follow is recorded as such, not dropped:
    /// parameters, attributes, call results and unknown path segments.
    #[test]
    fn tooth_reads_the_analysis_cannot_follow_are_opaque_or_open_never_silent() {
        let facts = py("import os, tempfile\nHERE = os.path.dirname(__file__)\n\
                        def helper(path):\n    return open(path).read()\n\
                        class Store:\n    def load(self):\n        return open(self.path).read()\n\
                        def by_name(name):\n    return open(os.path.join(HERE, name)).read()\n\
                        def computed():\n    return open(find_config()).read()\n\
                        def scratch():\n    tmp = tempfile.mkdtemp()\n    with open(os.path.join(tmp, 'out.txt'), 'w') as f:\n        f.write('x')\n\
                        \x20   with tempfile.TemporaryDirectory() as d:\n        open(os.path.join(d, 'y')).read()\n\
                        def formatted(n):\n    return open(f'fixtures/{n}.json').read() + open('%s/x' % HERE).read()\n");
        assert_eq!(
            reads(&facts),
            vec![
                read("open", "File", &[], false, true),
                read("open", "File", &[], false, true),
                read("open", "File", &["file^1/+"], false, false),
                read("open", "File", &[], false, true),
                // The two scratch-directory opens are provably not the tree: no site.
                read("open", "File", &["root^0/fixtures+"], false, false),
                read("open", "File", &[], true, false),
            ]
        );
    }

    #[test]
    fn names_flow_through_module_functions_loops_and_imports() {
        let facts =
            py("import os\nfrom tests.support import REPO as ROOT\nimport tests.support as support\nfrom . import layout\n\
                        def read(path):\n    return open(path).read()\n\
                        read(os.path.join(os.path.dirname(__file__), 'a.txt'))\n\
                        for part in (ROOT / 'one', support.REPO / 'two'):\n    part.read_text()\n\
                        x = open(layout.DATA / 'z')\n");
        let all = reads(&facts);
        // The parameter holds what the module's own call passes, and may hold anything else.
        assert_eq!(all[0], read("open", "File", &["file^1/a.txt"], false, true));
        assert_eq!(all[1], read(".read_text", "File", &["tests.support.REPO^0/one", "tests.support.REPO^0/two"], false, false));
        assert_eq!(all[2], read("open", "File", &[".layout.DATA^0/z"], false, false));
        // An imported name is offered on to importers of this module.
        assert!(facts
            .exports
            .iter()
            .any(|(name, reach)| name == "ROOT" && reach.places[0].anchor == Anchor::Name("tests.support.REPO".into())));
    }

    #[test]
    fn loaders_by_path_and_python_children_are_edges_when_literal() {
        let facts = py("import importlib.util, runpy, subprocess, sys, os\nREPO = os.path.dirname(os.path.dirname(__file__))\n\
                        spec = importlib.util.spec_from_file_location('tool', os.path.join(REPO, 'scripts', 'tool.py'))\n\
                        runpy.run_path(os.path.join(REPO, 'bin', 'fabc'))\n\
                        subprocess.run([sys.executable, os.path.join(REPO, 'scripts', 'run.py'), '--flag'])\n\
                        subprocess.run([sys.executable, '-m', 'fleetd.cli', 'status'])\n\
                        subprocess.run([sys.executable, '-c', 'print(1)'])\nsubprocess.run(['sh', 'x.sh'])\nos.system('make')\n\
                        spec2 = importlib.util.spec_from_file_location('m', path)\n");
        assert_eq!(
            reads(&facts),
            vec![
                read("importlib.util.spec_from_file_location", "Module", &["file^2/scripts/tool.py"], false, false),
                read("runpy.run_path", "Module", &["file^2/bin/fabc"], false, false),
                read("python child script", "Module", &["file^2/scripts/run.py"], false, false),
                read("subprocess.run", "Process", &[], false, true),
                read("subprocess.run", "Process", &[], false, true),
                read("os.system", "Process", &[], false, true),
                read("importlib.util.spec_from_file_location", "Module", &[], false, true),
            ]
        );
        assert!(facts.imports.iter().any(|i| i.module == "fleetd.cli"));
    }

    #[test]
    fn tooth_what_can_hide_a_loader_or_a_scan_is_a_dynamic_load() {
        let facts = py("from importlib import *\nfrom os import *\nfrom mylib import *\nimport sys, site, pkgutil\n\
                        sys.path.insert(0, 'scripts')\nsys.path = []\nsite.addsitedir('x')\nfor m in pkgutil.iter_modules(p): pass\neval(s)\n");
        let what: Vec<&str> = facts.dynamic_loads.iter().map(|d| d.what.as_str()).collect();
        assert_eq!(
            what,
            vec![
                "wildcard import of importlib",
                "wildcard import of os",
                "sys.path.insert",
                "sys.path assignment",
                "site.addsitedir",
                "pkgutil.iter_modules",
                "eval"
            ]
        );
    }

    #[test]
    fn replaces_and_alias_resolution() {
        let facts = py("import os, subprocess\nfrom os import replace as swap\n\
                        class Store:\n    def save(self, tmp, dst):\n        swap(tmp, dst)\n        os.rename(tmp, dst)\n\
                        text = 'a'.replace('a', 'b')\nsubprocess.run(['x'])\n");
        let replaces: Vec<(&str, &str, u32)> =
            facts.replaces.iter().map(|s| (s.what.as_str(), s.func.as_str(), s.line)).collect();
        assert_eq!(replaces, vec![("os.replace", "Store.save", 5), ("os.rename", "Store.save", 6)]);
        assert!(symbol(&facts, "os.replace", true).is_some());
        assert!(symbol(&facts, "swap", true).is_none());
        assert!(symbol(&facts, "subprocess.run", true).is_some());
    }

    #[test]
    fn flock_sites_know_nonblocking_and_poll_loops() {
        let facts = py("import fcntl, time\n\
                        def blocking(fd):\n    fcntl.flock(fd, fcntl.LOCK_EX)\n\
                        def nonblocking(fd):\n    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n\
                        def unbounded(fd):\n    while True:\n        try:\n            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n\
                        \x20           return\n        except OSError:\n            time.sleep(0.1)\n\
                        def bounded(fd, deadline):\n    while True:\n        try:\n            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n\
                        \x20           return\n        except OSError:\n            if time.monotonic() > deadline: raise\n            time.sleep(0.1)\n\
                        def release(fd):\n    fcntl.flock(fd, fcntl.LOCK_UN)\n\
                        def variable(fd, flags):\n    fcntl.flock(fd, flags)\n\
                        def condition(fd, done):\n    while not done():\n        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n        time.sleep(1)\n");
        let got: Vec<(&str, bool, bool, bool, bool, bool)> = facts
            .flocks
            .iter()
            .map(|f| (f.func.as_str(), f.nonblocking, f.unlock, f.polled, f.poll_bounded, f.flags_opaque))
            .collect();
        assert_eq!(
            got,
            vec![
                ("blocking", false, false, false, true, false),
                ("nonblocking", true, false, false, true, false),
                ("unbounded", true, false, true, false, false),
                ("bounded", true, false, true, true, false),
                ("release", false, true, false, true, false),
                // Flags in a variable are not read as "blocking".
                ("variable", false, false, false, true, true),
                // A loop condition is not a bound.
                ("condition", true, false, true, false, false),
            ]
        );
        assert_eq!(facts.flocks[0].call, "fcntl.flock");
    }

    #[test]
    fn strftime_sys_executable_settings_and_exceptions() {
        let facts = py("import sys, time\nfrom datetime import datetime\n\
                        stamp = time.strftime('%Y-%m-%d')\nwhen = datetime.strptime(text, '%H:%M')\ndyn = now.strftime(fmt)\n\
                        cmd = [sys.executable, '-m', 'pytest']\n\
                        a = setting('land.run.hub_cpu_s')\nb = cfg.or_default('fabd.route', 1)\nc = d.get('a.b')\n\
                        skip = d.get('plain')\nskip2 = d.get(name)\nskip3 = d.get('notes.txt ')\n\
                        class Worker:\n    def run(self):\n        try:\n            go()\n        except (OSError, ValueError) as err:\n\
                        \x20           self.failure = err\n            other = err\n        except KeyError:\n            self.x = 1\n");
        let formats: Vec<Option<&str>> = facts.strftimes.iter().map(|s| s.format.as_deref()).collect();
        assert_eq!(formats, vec![Some("%Y-%m-%d"), Some("%H:%M"), None]);
        assert_eq!(facts.sys_executable.len(), 1);
        assert_eq!(facts.sys_executable[0].line, 6);
        let reads: Vec<(&str, &str)> = facts.settings_reads.iter().map(|r| (r.reader.as_str(), r.key.as_str())).collect();
        assert_eq!(reads, vec![("setting", "land.run.hub_cpu_s"), ("or_default", "fabd.route"), ("get", "a.b")]);
        assert_eq!(facts.exc_on_self.len(), 1);
        assert_eq!(
            (facts.exc_on_self[0].func.as_str(), facts.exc_on_self[0].what.as_str()),
            ("Worker.run", "self.failure = err")
        );
    }

    #[test]
    fn tooth_bare_python_is_a_command_not_a_word() {
        let facts = py("import subprocess, sys\n\
                        subprocess.run('python -m build', shell=True)\nsubprocess.run(['python', 'tool.py'])\n\
                        subprocess.run('python3 -m build', shell=True)\nsubprocess.run([sys.executable, 'tool.py'])\n\
                        lang = 'python'\nlangs = ['rust', 'python']\nhelp = 'python is a language'\n\
                        def f():\n    'python -m docstring'\n");
        let lines: Vec<u32> = facts.bare_python.iter().map(|s| s.line).collect();
        assert_eq!(lines, vec![2, 3]);

        let recipe = extract(
            FileKind::Recipe,
            b"test:\n\tpython -m pytest\n\tpython3 -m pytest\n\t@python tool.py\n# python comment\n\
              run: python setup.py build\nlanguage: python\nx: cd a && python b.py\ny: $(python -c 'print(1)')\n\
              z: echo python is nice\n  - python -m x\npython_version: 3\n",
        );
        let lines: Vec<u32> = recipe.bare_python.iter().map(|s| s.line).collect();
        assert_eq!(lines, vec![2, 4, 6, 8, 9, 11]);
        assert_eq!(recipe.language, Language::Recipe);
    }

    #[test]
    fn function_body_hash_ignores_layout_comments_and_docstrings() {
        let a = py("def atomic_write(path, data):\n    tmp = path + '.tmp'\n    write(tmp, data)\n    os.replace(tmp, path)\n");
        let b = py("class K:\n    def copy(self, path, data):\n        \"\"\"Doc.\"\"\"\n        # comment\n        tmp = path + '.tmp'\n\n\
                    \x20       write(tmp,\n              data)\n        os.replace(tmp, path)  # trailing\n");
        let c = py("def atomic_write(path, data):\n    tmp = path + '.part'\n    write(tmp, data)\n    os.replace(tmp, path)\n");
        assert_eq!(a.functions[0].name, "atomic_write");
        assert_eq!(b.functions[0].name, "K.copy");
        assert_eq!(a.functions[0].statements, 3);
        assert_eq!(b.functions[0].statements, 3);
        assert_eq!(a.functions[0].body_hash, b.functions[0].body_hash);
        assert_ne!(a.functions[0].body_hash, c.functions[0].body_hash);
    }

    #[test]
    fn symbols_are_calls_and_references_to_imported_names() {
        let facts = py("import subprocess as sp\nimport os\nfrom land import stopfacts\nfrom . import sibling\n\
                        def run(cmd, check=DEFAULT):\n    sp.run(cmd)\n    sp.run(cmd, check=check)\n    env = os.environ\n\
                        \x20   reader = stopfacts\n    sibling.go()\n    return helper(cmd).stdout.strip()\n\
                        value = f'{compute(1)} and {other} {os.sep}'\n");
        let run = symbol(&facts, "subprocess.run", true).unwrap();
        assert_eq!((run.line, run.count), (6, 2));
        assert!(symbol(&facts, "helper", true).is_some());
        assert!(symbol(&facts, "compute", true).is_some());
        assert!(symbol(&facts, "os.environ", false).is_some());
        assert!(symbol(&facts, "os.sep", false).is_some());
        assert!(symbol(&facts, "land.stopfacts", false).is_some());
        // A relative import keeps its dots until a tree says where the file sits.
        assert!(symbol(&facts, ".sibling.go", true).is_some());
        // Locals, parameters, keyword names and defaults are not facts.
        for local in ["other", "DEFAULT", "check", "cmd", "env", "reader", "value"] {
            assert!(symbol(&facts, local, false).is_none(), "{local}");
        }
        let names: Vec<&str> = facts.symbols.iter().map(|s| s.name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }

    #[test]
    fn tooth_broken_syntax_and_bad_bytes_are_flagged_not_trusted() {
        let facts = py("import os\ndef ok():\n    os.replace(a, b)\n\ndef broken(:\n    ???\n");
        assert!(facts.parse_error);
        assert_eq!(facts.imports.len(), 1);
        assert_eq!(facts.replaces.len(), 1);
        assert!(!py("x = 1\n").parse_error);
        // A byte order mark is not an error; bytes that are not UTF-8 are.
        let with_bom = extract(FileKind::Python, b"\xef\xbb\xbfimport os\n");
        assert!(!with_bom.parse_error && with_bom.imports.len() == 1);
        let latin1 = extract(FileKind::Python, b"import os\nname = 'caf\xe9'\n");
        assert!(latin1.parse_error);
        // Identifiers outside ASCII are ordinary names.
        let unicode = py("import \u{e9}t\u{e9}\nfrom \u{f1}.mod import x\n");
        assert_eq!(unicode.imports[0].module, "\u{e9}t\u{e9}");
        assert!(!unicode.parse_error);
    }

    #[test]
    fn tooth_pathological_nesting_is_truncated_not_a_crash() {
        let deep = format!("x = {}1{}\n", "(".repeat(4000), ")".repeat(4000));
        let facts = std::thread::Builder::new().stack_size(32 << 20).spawn(move || py(&deep)).unwrap().join().unwrap();
        assert!(facts.truncated);
    }

    #[test]
    fn executables_are_sniffed_and_links_keep_their_target() {
        let tool = extract(FileKind::Sniff, b"#!/usr/bin/env python3\nimport os\nos.replace('a', 'b')\n");
        assert_eq!((tool.language, tool.imports.len(), tool.replaces.len()), (Language::Python, 1, 1));
        let shell = extract(FileKind::Sniff, b"#!/bin/sh\npython -m build\n");
        assert_eq!((shell.language, shell.bare_python.len()), (Language::Recipe, 1));
        let env_bash = extract(FileKind::Sniff, b"#!/usr/bin/env bash\npython x.py\n");
        assert_eq!(env_bash.language, Language::Recipe);
        let other = extract(FileKind::Sniff, b"MIT License\n\nimport nothing\n");
        assert_eq!(other, FileFacts::default());
        let link = extract(FileKind::Link, b"../scripts/tool.py");
        assert_eq!(link.link_target.as_deref(), Some("../scripts/tool.py"));
        assert!(extract(FileKind::Link, b"bad\xff").parse_error);
    }
}
