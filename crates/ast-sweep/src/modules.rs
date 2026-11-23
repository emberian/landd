//! Literal source dependencies. Unknown syntax and unresolved loads widen a cone.
use crate::facts::{FileFacts, FileKind};
use crate::imports::link_destination;
use std::path::Path;

pub fn supported(kind: FileKind) -> bool {
    matches!(kind, FileKind::TypeScript | FileKind::Tsx | FileKind::Lean | FileKind::Rust)
}

pub fn extract(kind: FileKind, source: &[u8]) -> FileFacts {
    let mut facts = FileFacts::default();
    let Ok(text) = std::str::from_utf8(source) else {
        facts.parse_error = true;
        return facts;
    };
    if kind == FileKind::Lean {
        // Strip nested Lean block comments before reading the module header.
        let mut depth = 0usize;
        for line in text.lines() {
            let mut header = String::new();
            let mut chars = line.chars().peekable();
            while let Some(ch) = chars.next() {
                match (ch, chars.peek()) {
                    ('/', Some('-')) => {
                        chars.next();
                        depth += 1;
                        header.push(' ');
                    }
                    ('-', Some('/')) if depth > 0 => {
                        chars.next();
                        depth -= 1;
                    }
                    ('-', Some('-')) if depth == 0 => break,
                    _ if depth == 0 => header.push(ch),
                    _ => {}
                }
            }
            let mut words = header.split_whitespace().peekable();
            while matches!(words.peek(), Some(&"public" | &"meta" | &"private" | &"all")) {
                words.next();
            }
            match words.next() {
                None | Some("module" | "prelude") => {}
                Some("import") => {
                    if words.peek().is_none() {
                        facts.parse_error = true;
                    }
                    facts.module_paths.extend(words.filter(|s| *s != "all").map(str::to_owned))
                }
                _ => break,
            }
        }
        facts.parse_error |= depth != 0;
        return facts;
    }
    let lang = match kind {
        FileKind::Rust => tree_sitter_rust::LANGUAGE,
        FileKind::Tsx => tree_sitter_typescript::LANGUAGE_TSX,
        _ => tree_sitter_typescript::LANGUAGE_TYPESCRIPT,
    };
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&lang.into()).expect("pinned grammar ABI");
    let Some(tree) = parser.parse(source, None) else {
        facts.parse_error = true;
        return facts;
    };
    facts.parse_error = tree.root_node().has_error();
    let mut cursor = tree.walk();
    loop {
        let n = cursor.node();
        let field = |key| n.child_by_field_name(key);
        let string = match n.kind() {
            "import_statement" | "export_statement" => field("source"),
            "call_expression" if field("function").is_some_and(|f| f.kind() == "import") => {
                let arg = field("arguments").and_then(|args| args.named_child(0));
                if arg.is_none_or(|arg| arg.kind() != "string") {
                    facts.parse_error = true;
                }
                arg
            }
            "mod_item" if field("body").is_none() => {
                if let Some(name) = field("name") {
                    let mut explicit = None;
                    let mut attr = n.prev_named_sibling();
                    while let Some(a) = attr {
                        if matches!(a.kind(), "line_comment" | "block_comment") {
                            attr = a.prev_named_sibling();
                            continue;
                        }
                        if a.kind() != "attribute_item" {
                            break;
                        }
                        let spec = text[a.byte_range()].trim_start_matches("#[").trim_end_matches(']').trim();
                        if let Some((key, val)) = spec.split_once('=') {
                            if key.trim() == "path" {
                                explicit = val.trim().strip_prefix('"').and_then(|v| v.strip_suffix('"'));
                                if explicit.is_none() {
                                    facts.parse_error = true;
                                }
                            }
                        }
                        attr = a.prev_named_sibling();
                    }
                    let mut parts = vec![explicit.unwrap_or(&text[name.byte_range()])];
                    let mut parent = n.parent();
                    while let Some(node) = parent {
                        if node.kind() == "mod_item" {
                            if let Some(name) = node.child_by_field_name("name") {
                                parts.push(&text[name.byte_range()]);
                            }
                        }
                        parent = node.parent();
                    }
                    parts.reverse();
                    facts.module_paths.push(if explicit.is_some() { format!("@{}", parts.join("/")) } else { parts.join("/") });
                }
                None
            }
            "attribute_item" if text[n.byte_range()].contains("cfg_attr") && text[n.byte_range()].contains("path") => {
                facts.parse_error = true;
                None
            }
            "macro_invocation" if field("macro").is_some_and(|m| text[m.byte_range()].starts_with("include")) => {
                facts.parse_error = true;
                None
            }
            _ => None,
        };
        if let Some(node) = string.filter(|n| n.kind() == "string") {
            let raw = &text[node.byte_range()];
            if raw.len() >= 2 {
                facts.module_paths.push(raw[1..raw.len() - 1].to_owned());
            }
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return facts;
            }
        }
    }
}

pub fn resolve(kind: FileKind, importer: &str, name: &str, roots: &[String]) -> Vec<String> {
    let source = Path::new(importer);
    let dir = source.parent().unwrap_or(Path::new(""));
    if kind == FileKind::Lean {
        let file = format!("{}.lean", name.replace('.', "/"));
        return std::iter::once(file.clone())
            .chain(roots.iter().map(|r| Path::new(r).join(&file).display().to_string()))
            .collect();
    }
    if kind == FileKind::Rust {
        if let Some(relative) = name.strip_prefix('@') {
            return link_destination(dir.to_str().unwrap_or(""), relative).into_iter().collect();
        }
        let dir = match source.file_name().and_then(|s| s.to_str()) {
            Some("lib.rs" | "main.rs" | "mod.rs") => dir.to_owned(),
            _ => source.with_extension(""),
        };
        let stem = dir.join(name);
        return vec![stem.with_extension("rs").display().to_string(), stem.join("mod.rs").display().to_string()];
    }
    if !(name.starts_with("./") || name.starts_with("../")) {
        return vec![];
    }
    let Some(path) = link_destination(dir.to_str().unwrap_or(""), name) else { return vec![] };
    let path = Path::new(&path);
    let mut candidates = vec![path.display().to_string()];
    let exts = ["ts", "tsx", "mts", "js", "mjs"];
    match path.extension().and_then(|e| e.to_str()) {
        None => {
            for ext in exts {
                candidates.push(path.with_extension(ext).display().to_string());
                candidates.push(path.join(format!("index.{ext}")).display().to_string());
            }
        }
        Some("js" | "mjs") => candidates.extend(exts[..3].iter().map(|ext| path.with_extension(ext).display().to_string())),
        _ => {}
    }
    candidates
}
#[cfg(test)]
mod tests {
    use crate::{imports::cones, AllFacts, ImportConfig, ImportGraph};
    use landd_core::Digest32;
    fn closure(files: &[(&str, &str)], root: &str, expected: &[&str]) {
        let all = AllFacts::from_sources(files);
        let config = ImportConfig { tests: vec![root.into()], always: vec![], ..ImportConfig::default() };
        let graph = ImportGraph::build(&all, &config);
        let result = cones(&all, &graph, &config, &Digest32::blake3(b"runner"));
        assert!(!result[0].widened, "{:?}", result[0].causes);
        assert_eq!(result[0].input_paths(&all).collect::<Vec<_>>(), expected);
    }
    #[test]
    fn transitive_diamonds_and_cycles() {
        closure(
            &[
                ("a.ts", "import './b'; export * from './c.mjs'"),
                ("b.tsx", "import('./d')"),
                ("c.mts", "import './d/index.js'"),
                ("d/index.js", "import '../a'"),
                ("other.ts", ""),
            ],
            "a.ts",
            &["a.ts", "b.tsx", "c.mts", "d/index.js"],
        );
        closure(
            &[
                ("A.lean", "module\npublic import B\nimport C"),
                ("B.lean", "import D"),
                ("C.lean", "import D"),
                ("D.lean", "import A"),
                ("E.lean", ""),
            ],
            "A.lean",
            &["A.lean", "B.lean", "C.lean", "D.lean"],
        );
        closure(
            &[
                ("lib.rs", "mod b; mod c;"),
                ("b.rs", "#[path=\"d.rs\"] mod shared;"),
                ("c/mod.rs", "#[path=\"../d.rs\"] mod shared;"),
                ("d.rs", "#[path=\"lib.rs\"] mod root;"),
                ("other.rs", ""),
            ],
            "lib.rs",
            &["b.rs", "c/mod.rs", "d.rs", "lib.rs"],
        );
    }
}
