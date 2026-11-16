//! The per-blob `Map` pass: bytes in, [`FileFacts`] out.
//!
//! Python is parsed with tree-sitter, which recovers from syntax errors, so a
//! half-broken file still yields the facts of everything that did parse.
//! Recipe files are scanned by line.
//!
//! Two facts are heuristics over source text and say so here:
//!
//! * a loop "sleeps" when its text contains `sleep(`;
//! * a sleeping loop is "bounded" when it is a `for`, or its `while`
//!   condition is not the constant `True`/`1`, or its text mentions a bound
//!   (`deadline`, `timeout`, `monotonic(`, `time.time(`, `attempt`, `retries`,
//!   `tries`).

use crate::facts::*;
use landd_core::Digest32;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use tree_sitter::{Node, Parser};

/// Deeper syntax than this is not walked; the file is marked `truncated`.
const MAX_DEPTH: usize = 1200;
const BOUND_HINTS: [&str; 7] = ["deadline", "timeout", "monotonic(", "time.time(", "attempt", "retries", "tries"];
const BODY_HASH_DOMAIN: &str = "ast-sweep function body v1";

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
        FileKind::Recipe => extract_recipe(source),
    }
}

fn extract_python(source: &[u8]) -> FileFacts {
    let Some(tree) = PARSER.with(|parser| parser.borrow_mut().parse(source, None)) else {
        return FileFacts { parse_error: true, ..FileFacts::default() };
    };
    let root = tree.root_node();
    let mut walker = Walker {
        src: source,
        facts: FileFacts { parse_error: root.has_error(), ..FileFacts::default() },
        aliases: HashMap::new(),
        symbols: BTreeMap::new(),
        scope: Vec::new(),
        loops: Vec::new(),
        caught: Vec::new(),
    };
    walker.visit(root, 0);
    let Walker { mut facts, symbols, .. } = walker;
    facts.symbols =
        symbols.into_iter().map(|((name, call), (line, count))| SymbolRef { name, call, line, count }).collect();
    facts
}

struct Loop {
    sleeps: bool,
    bounded: bool,
}

struct Walker<'s> {
    src: &'s [u8],
    facts: FileFacts,
    /// Local name -> the dotted name it was imported as.
    aliases: HashMap<&'s str, String>,
    symbols: BTreeMap<(String, bool), (u32, u32)>,
    scope: Vec<&'s str>,
    loops: Vec<Loop>,
    /// Names bound by the enclosing `except … as name` clauses.
    caught: Vec<&'s str>,
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

impl<'s> Walker<'s> {
    fn text(&self, node: Node) -> &'s str {
        node.utf8_text(self.src).unwrap_or("")
    }

    fn func(&self) -> String {
        self.scope.join(".")
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

    fn children(&mut self, node: Node, depth: usize) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            self.visit(child, depth + 1);
        }
    }

    fn visit_field(&mut self, node: Node, field: &str, depth: usize) {
        if let Some(child) = node.child_by_field_name(field) {
            self.visit(child, depth + 1);
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
            "function_definition" => self.function(node, depth),
            "class_definition" => {
                self.scope.push(node.child_by_field_name("name").map(|n| self.text(n)).unwrap_or(""));
                self.visit_field(node, "superclasses", depth);
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
                    let mut cursor = node.walk();
                    let pattern = node.named_children(&mut cursor).find(|c| c.kind() == "as_pattern");
                    pattern.and_then(|p| p.child_by_field_name("alias"))
                });
                self.caught.push(alias.map(|a| self.text(a)).unwrap_or(""));
                self.children(node, depth);
                self.caught.pop();
            }
            "assignment" => {
                self.assignment(node);
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
    /// facts; locals, parameters and attributes of locals are not.
    fn reference(&mut self, node: Node, name: String) {
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

    fn import(&mut self, node: Node) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            let module = match child.kind() {
                "dotted_name" => {
                    // `import a.b` binds `a`.
                    let head = self.text(child).split('.').next().unwrap_or("");
                    self.aliases.entry(head).or_insert_with(|| head.to_owned());
                    self.text(child)
                }
                "aliased_import" => {
                    let Some(name) = child.child_by_field_name("name") else { continue };
                    if let Some(alias) = child.child_by_field_name("alias") {
                        self.aliases.insert(self.text(alias), self.text(name).to_owned());
                    }
                    self.text(name)
                }
                _ => continue,
            };
            self.facts.imports.push(Import { module: module.to_owned(), level: 0, names: Vec::new(), line: line_of(node) });
        }
    }

    fn import_from(&mut self, node: Node) {
        let (mut level, mut module) = (0u8, "");
        if let Some(source) = node.child_by_field_name("module_name") {
            if source.kind() == "relative_import" {
                let mut cursor = source.walk();
                for part in source.named_children(&mut cursor) {
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
        let mut names = Vec::new();
        let mut cursor = node.walk();
        for child in node.children_by_field_name("name", &mut cursor) {
            let (name, local) = match child.kind() {
                "aliased_import" => {
                    let name = child.child_by_field_name("name").map(|n| self.text(n)).unwrap_or("");
                    (name, child.child_by_field_name("alias").map(|a| self.text(a)).unwrap_or(name))
                }
                _ => (self.text(child), self.text(child)),
            };
            if level == 0 && !name.is_empty() {
                self.aliases.insert(local, format!("{module}.{name}"));
            }
            names.push(name.to_owned());
        }
        let mut cursor = node.walk();
        if node.named_children(&mut cursor).any(|c| c.kind() == "wildcard_import") {
            names.push("*".to_owned());
        }
        self.facts.imports.push(Import { module: module.to_owned(), level, names, line: line_of(node) });
    }

    fn function(&mut self, node: Node, depth: usize) {
        self.scope.push(node.child_by_field_name("name").map(|n| self.text(n)).unwrap_or(""));
        if let Some(body) = node.child_by_field_name("body") {
            let (body_hash, statements) = hash_body(body, self.src);
            self.facts.functions.push(FunctionFact { name: self.func(), line: line_of(node), body_hash, statements });
        }
        // A nested function is not "inside" the loop or handler that defines it.
        let loops = std::mem::take(&mut self.loops);
        let caught = std::mem::take(&mut self.caught);
        self.visit_field(node, "parameters", depth);
        self.visit_field(node, "return_type", depth);
        self.visit_field(node, "body", depth);
        self.loops = loops;
        self.caught = caught;
        self.scope.pop();
    }

    /// Parameter names are bindings, not references; defaults and
    /// annotations are expressions.
    fn parameters(&mut self, node: Node, depth: usize) {
        let mut cursor = node.walk();
        for parameter in node.named_children(&mut cursor) {
            self.visit_field(parameter, "value", depth);
            self.visit_field(parameter, "type", depth);
        }
    }

    fn loop_info(&self, node: Node) -> Loop {
        let text = self.text(node);
        let constant_true = node
            .child_by_field_name("condition")
            .map(|c| matches!(self.text(c).trim_matches(['(', ')', ' ']), "True" | "1"))
            .unwrap_or(false);
        Loop {
            sleeps: text.contains("sleep("),
            bounded: node.kind() == "for_statement" || !constant_true || BOUND_HINTS.iter().any(|h| text.contains(h)),
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
    }

    /// The literal value of a string with no interpolation.
    fn literal(&self, node: Node) -> Option<String> {
        match node.kind() {
            "string" => {
                let mut out = String::new();
                let mut cursor = node.walk();
                for part in node.children(&mut cursor) {
                    match part.kind() {
                        "string_content" => out.push_str(self.text(part)),
                        "interpolation" => return None,
                        _ => {}
                    }
                }
                Some(out)
            }
            "concatenated_string" => {
                let mut out = String::new();
                let mut cursor = node.walk();
                for part in node.named_children(&mut cursor) {
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
            if value == "ls-files" || value.contains("git ls-files") {
                let site = self.site(node, "git ls-files");
                self.facts.scans.push(site);
            }
            return;
        }
        // An f-string: its interpolations are expressions.
        let mut stack = vec![node];
        while let Some(current) = stack.pop() {
            let mut cursor = current.walk();
            for part in current.named_children(&mut cursor) {
                match part.kind() {
                    "interpolation" => self.children(part, depth),
                    "string" => stack.push(part),
                    _ => {}
                }
            }
        }
    }

    fn call(&mut self, node: Node, depth: usize) {
        let Some(function) = node.child_by_field_name("function") else {
            return self.children(node, depth);
        };
        let arguments = node.child_by_field_name("arguments");
        let full = self.dotted(function).map(|name| self.resolve(name));
        let method = function.kind() == "attribute";
        let last: String = match &full {
            Some(name) => name.rsplit('.').next().unwrap_or("").to_owned(),
            None if method => function.child_by_field_name("attribute").map(|a| self.text(a)).unwrap_or("").to_owned(),
            None => String::new(),
        };
        let name = full.as_deref().unwrap_or("");

        let mut positional = Vec::new();
        if let Some(arguments) = arguments.filter(|a| a.kind() == "argument_list") {
            let mut cursor = arguments.walk();
            positional.extend(arguments.named_children(&mut cursor).filter(|a| {
                !matches!(a.kind(), "keyword_argument" | "comment" | "list_splat" | "dictionary_splat")
            }));
        }
        let first_literal = positional.first().and_then(|a| self.literal(*a));
        let arguments_text = arguments.map(|a| self.text(a)).unwrap_or("");

        match name {
            "importlib.import_module" | "__import__" | "importlib.__import__" => match &first_literal {
                Some(target) => {
                    let level = target.bytes().take_while(|b| *b == b'.').count();
                    self.facts.imports.push(Import {
                        module: target[level..].to_owned(),
                        level: level.min(255) as u8,
                        names: Vec::new(),
                        line: line_of(node),
                    });
                }
                None => {
                    let site = self.site(node, name);
                    self.facts.dynamic_loads.push(site);
                }
            },
            "importlib.util.spec_from_file_location"
            | "importlib.machinery.SourceFileLoader"
            | "runpy.run_path"
            | "runpy.run_module"
            | "imp.load_source"
            | "imp.load_module"
            | "pkgutil.iter_modules"
            | "pkgutil.walk_packages"
            | "exec"
            | "execfile" => {
                let site = self.site(node, name);
                self.facts.dynamic_loads.push(site);
            }
            "os.walk" | "os.fwalk" | "os.listdir" | "os.scandir" | "glob.glob" | "glob.iglob" => {
                let site = self.site(node, name);
                self.facts.scans.push(site);
            }
            "os.replace" | "os.rename" => {
                let site = self.site(node, name);
                self.facts.replaces.push(site);
            }
            _ => {}
        }
        if method && matches!(last.as_str(), "rglob" | "iterdir" | "glob") && !name.starts_with("glob.") {
            let site = self.site(node, format!(".{last}"));
            self.facts.scans.push(site);
        }
        if matches!(last.as_str(), "flock" | "lockf") {
            let sleeping: Vec<&Loop> = self.loops.iter().filter(|l| l.sleeps).collect();
            self.facts.flocks.push(FlockSite {
                line: line_of(node),
                func: self.func(),
                call: if name.is_empty() { format!(".{last}") } else { name.to_owned() },
                nonblocking: arguments_text.contains("LOCK_NB"),
                unlock: arguments_text.contains("LOCK_UN"),
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
    let mut facts = FileFacts::default();
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

    #[test]
    fn imports_in_every_spelling() {
        let facts = py("import os\nimport a.b.c as abc, json\nfrom x.y import z, w as v\nfrom . import sib\n\
                        from ..pkg.mod import thing\nfrom m import *\nfrom __future__ import annotations\n\
                        def f():\n    import late\n");
        let got: Vec<(&str, u8, Vec<&str>)> = facts
            .imports
            .iter()
            .map(|i| (i.module.as_str(), i.level, i.names.iter().map(String::as_str).collect()))
            .collect();
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
        assert!(!facts.parse_error);
    }

    #[test]
    fn tooth_literal_import_module_is_static_and_computed_is_taint() {
        let facts = py("import importlib\nfrom importlib import import_module as im\n\
                        a = importlib.import_module('pkg.plugin')\nb = im(name)\nc = __import__('json')\n\
                        exec(code)\nd = importlib.import_module('.rel', __package__)\n");
        let static_targets: Vec<(&str, u8)> =
            facts.imports.iter().skip(2).map(|i| (i.module.as_str(), i.level)).collect();
        assert_eq!(static_targets, vec![("pkg.plugin", 0), ("json", 0), ("rel", 1)]);
        let dynamic: Vec<(&str, u32)> = facts.dynamic_loads.iter().map(|s| (s.what.as_str(), s.line)).collect();
        assert_eq!(dynamic, vec![("importlib.import_module", 4), ("exec", 6)]);
        assert!(py("import importlib\nx = importlib.import_module('a.b')\n").dynamic_loads.is_empty());
    }

    #[test]
    fn scans_replaces_and_alias_resolution() {
        let facts = py("import os, glob, subprocess\nfrom os import replace as swap, walk\nfrom pathlib import Path\n\
                        class Store:\n    def save(self, tmp, dst):\n        swap(tmp, dst)\n        os.rename(tmp, dst)\n\
                        def scan(root):\n    for _ in walk(root): pass\n    glob.glob('*.py')\n    Path(root).rglob('*.py')\n\
                        \x20   subprocess.run(['git', 'ls-files'])\n    return os.listdir(root)\n\
                        text = 'a'.replace('a', 'b')\n");
        let replaces: Vec<(&str, &str, u32)> =
            facts.replaces.iter().map(|s| (s.what.as_str(), s.func.as_str(), s.line)).collect();
        assert_eq!(replaces, vec![("os.replace", "Store.save", 6), ("os.rename", "Store.save", 7)]);
        let scans: Vec<&str> = facts.scans.iter().map(|s| s.what.as_str()).collect();
        assert_eq!(scans, vec!["os.walk", "glob.glob", ".rglob", "git ls-files", "os.listdir"]);
        assert!(facts.scans.iter().all(|s| s.func == "scan"));
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
                        def release(fd):\n    fcntl.flock(fd, fcntl.LOCK_UN)\n");
        let got: Vec<(&str, bool, bool, bool, bool)> = facts
            .flocks
            .iter()
            .map(|f| (f.func.as_str(), f.nonblocking, f.unlock, f.polled, f.poll_bounded))
            .collect();
        assert_eq!(
            got,
            vec![
                ("blocking", false, false, false, true),
                ("nonblocking", true, false, false, true),
                ("unbounded", true, false, true, false),
                ("bounded", true, false, true, true),
                ("release", false, true, false, true),
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
                        skip = d.get('plain')\nskip2 = d.get(name)\nskip3 = open('notes.txt ')\n\
                        class Worker:\n    def run(self):\n        try:\n            go()\n        except (OSError, ValueError) as err:\n\
                        \x20           self.failure = err\n            other = err\n        except KeyError:\n            self.x = 1\n");
        let formats: Vec<Option<&str>> = facts.strftimes.iter().map(|s| s.format.as_deref()).collect();
        assert_eq!(formats, vec![Some("%Y-%m-%d"), Some("%H:%M"), None]);
        assert_eq!(facts.sys_executable.len(), 1);
        assert_eq!(facts.sys_executable[0].line, 6);
        let reads: Vec<(&str, &str)> = facts.settings_reads.iter().map(|r| (r.reader.as_str(), r.key.as_str())).collect();
        assert_eq!(reads, vec![("setting", "land.run.hub_cpu_s"), ("or_default", "fabd.route"), ("get", "a.b")]);
        assert_eq!(facts.exc_on_self.len(), 1);
        assert_eq!((facts.exc_on_self[0].func.as_str(), facts.exc_on_self[0].what.as_str()), ("Worker.run", "self.failure = err"));
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
        let facts = py("import subprocess as sp\nimport os\nfrom land import stopfacts\n\
                        def run(cmd, check=DEFAULT):\n    sp.run(cmd)\n    sp.run(cmd, check=check)\n    env = os.environ\n\
                        \x20   reader = stopfacts\n    return helper(cmd).stdout.strip()\n\
                        value = f'{compute(1)} and {other} {os.sep}'\n");
        let run = symbol(&facts, "subprocess.run", true).unwrap();
        assert_eq!((run.line, run.count), (5, 2));
        assert!(symbol(&facts, "helper", true).is_some());
        assert!(symbol(&facts, "compute", true).is_some());
        assert!(symbol(&facts, "os.environ", false).is_some());
        assert!(symbol(&facts, "os.sep", false).is_some());
        assert!(symbol(&facts, "land.stopfacts", false).is_some());
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
    fn tooth_broken_syntax_still_yields_facts_and_says_so() {
        let facts = py("import os\ndef ok():\n    os.replace(a, b)\n\ndef broken(:\n    ???\n");
        assert!(facts.parse_error);
        assert_eq!(facts.imports.len(), 1);
        assert_eq!(facts.replaces.len(), 1);
        assert!(!py("x = 1\n").parse_error);
    }

    #[test]
    fn tooth_pathological_nesting_is_truncated_not_a_crash() {
        let deep = format!("x = {}1{}\n", "(".repeat(4000), ")".repeat(4000));
        let facts = std::thread::Builder::new()
            .stack_size(32 << 20)
            .spawn(move || py(&deep))
            .unwrap()
            .join()
            .unwrap();
        assert!(facts.truncated);
    }
}
