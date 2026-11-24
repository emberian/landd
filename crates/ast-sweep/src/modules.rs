//! Literal source dependencies. Unknown syntax and unresolved loads widen a cone.
use crate::facts::{DynamicLoad, FileFacts, FileKind, PackageJsonFacts, TsConfigFacts};
use crate::imports::link_destination;
use crate::rules::{BareImports, ImportConfig};
use crate::sweep::AllFacts;
use oxc_allocator::Allocator;
use oxc_ast::ast::Expression;
use oxc_parser::{config::TokensParserConfig, Kind, ParseOptions, Parser, Token};
use oxc_span::SourceType;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

/// Unambiguous Node.js core built-in modules that never resolve to repository source files or npm packages.
const NODE_BUILTINS: &[&str] = &[
    "assert",
    "async_hooks",
    "child_process",
    "cluster",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "domain",
    "events",
    "fs",
    "http",
    "http2",
    "https",
    "inspector",
    "module",
    "net",
    "os",
    "path",
    "perf_hooks",
    "querystring",
    "readline",
    "repl",
    "stream",
    "string_decoder",
    "timers",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
    "zlib",
];

/// Lockfiles checked in priority order at each ancestor directory for bare external package specifiers.
const LOCKFILES: [&str; 7] =
    ["pnpm-lock.yaml", "package-lock.json", "yarn.lock", "bun.lock", "bun.lockb", "deno.lock", "Cargo.lock"];

/// Extensions probed when a TypeScript/JavaScript import omits a source extension (including dot-in-stem files).
const PROBE_EXTS: [&str; 9] = ["ts", "tsx", "mts", "cts", "d.ts", "js", "jsx", "mjs", "cjs"];

/// Complete module extensions that do not undergo extensionless suffix appending.
const KNOWN_MODULE_EXTS: [&str; 10] = ["ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs", "json", "css"];

pub fn supported(kind: FileKind) -> bool {
    matches!(kind, FileKind::TypeScript | FileKind::Tsx | FileKind::Dts | FileKind::Lean | FileKind::Rust)
}

pub fn extract(kind: FileKind, source: &[u8]) -> FileFacts {
    match kind {
        FileKind::TypeScript | FileKind::Tsx | FileKind::Dts => return extract_ts_js(kind, source),
        FileKind::TsConfig => return extract_tsconfig(source),
        FileKind::PackageJson => return extract_package_json(source),
        _ => {}
    }
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

    // Rust module declarations via tree-sitter-rust.
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&tree_sitter_rust::LANGUAGE.into()).expect("pinned grammar ABI");
    let Some(tree) = parser.parse(source, None) else {
        facts.parse_error = true;
        return facts;
    };
    facts.parse_error = tree.root_node().has_error();
    let mut cursor = tree.walk();
    loop {
        let n = cursor.node();
        let field = |key| n.child_by_field_name(key);
        match n.kind() {
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
            }
            "attribute_item" if text[n.byte_range()].contains("cfg_attr") && text[n.byte_range()].contains("path") => {
                facts.parse_error = true;
            }
            "macro_invocation" if field("macro").is_some_and(|m| text[m.byte_range()].starts_with("include")) => {
                facts.parse_error = true;
            }
            _ => {}
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

fn unwrap_parens<'a, 'b>(mut expr: &'b Expression<'a>) -> &'b Expression<'a> {
    while let Expression::ParenthesizedExpression(paren) = expr {
        expr = &paren.expression;
    }
    expr
}

fn decode_str_token(allocator: &Allocator, text: &str, tok: &Token) -> Option<String> {
    if tok.kind() != Kind::Str {
        return None;
    }
    let raw = text.get(tok.start() as usize..tok.end() as usize)?;
    if !tok.escaped() {
        return (raw.len() >= 2).then(|| raw[1..raw.len() - 1].to_owned());
    }
    match Parser::new(allocator, raw, SourceType::ts()).parse_expression().ok()? {
        Expression::StringLiteral(lit) => Some(lit.value.as_str().to_owned()),
        _ => None,
    }
}

fn extract_ts_js(kind: FileKind, source: &[u8]) -> FileFacts {
    let source = source.strip_prefix(b"\xef\xbb\xbf").unwrap_or(source);
    let Ok(text) = std::str::from_utf8(source) else {
        return FileFacts { parse_error: true, ..FileFacts::default() };
    };
    let allocator = Allocator::default();
    let options = ParseOptions { allow_return_outside_function: true, ..ParseOptions::default() };
    let primary_type = match kind {
        FileKind::Tsx => SourceType::tsx().with_module(true),
        FileKind::Dts => SourceType::d_ts(),
        _ => SourceType::ts().with_module(true),
    };
    let mut ret = Parser::new(&allocator, text, primary_type).with_options(options).with_config(TokensParserConfig).parse();
    if (ret.panicked || !ret.errors.is_empty()) && kind == FileKind::TypeScript && !ret.module_record.has_module_syntax {
        let fallback =
            Parser::new(&allocator, text, SourceType::cjs()).with_options(options).with_config(TokensParserConfig).parse();
        if !fallback.panicked && fallback.errors.is_empty() {
            ret = fallback;
        }
    }

    let mut facts = FileFacts { parse_error: ret.panicked || !ret.errors.is_empty(), ..FileFacts::default() };
    let mut seen = HashSet::new();
    let mut push_spec = |spec: String| {
        if seen.insert(spec.clone()) {
            facts.module_paths.push(spec);
        }
    };

    // 1. Static `import`, `import type`, `export ... from`, `export * from`, `export type * from` in source order.
    let mut static_reqs: Vec<(u32, &str)> = ret
        .module_record
        .requested_modules
        .iter()
        .map(|(spec, occs)| (occs.first().map_or(0, |o| o.span.start), spec.as_str()))
        .collect();
    static_reqs.sort_unstable_by_key(|(pos, _)| *pos);
    for (_, spec) in static_reqs {
        push_spec(spec.to_owned());
    }

    // 2. Dynamic `import(...)` expressions: literal string / substitution-free template -> `module_paths`,
    //    computed expression -> `dynamic_loads` (without falsely marking `parse_error`).
    let mut dyn_starts = HashSet::with_capacity(ret.module_record.dynamic_imports.len());
    for dyn_imp in &ret.module_record.dynamic_imports {
        dyn_starts.insert(dyn_imp.span.start);
        let req_src = text.get(dyn_imp.module_request.start as usize..dyn_imp.module_request.end as usize).unwrap_or("");
        let parsed = Parser::new(&allocator, req_src, primary_type).parse_expression();
        match parsed.as_ref().map(unwrap_parens) {
            Ok(Expression::StringLiteral(lit)) => push_spec(lit.value.as_str().to_owned()),
            Ok(Expression::TemplateLiteral(tpl)) if tpl.expressions.is_empty() => {
                if let Some(cooked) = tpl.quasis.first().and_then(|q| q.value.cooked) {
                    push_spec(cooked.as_str().to_owned());
                }
            }
            other => {
                let prefix = match other {
                    Ok(Expression::TemplateLiteral(tpl)) => {
                        tpl.quasis.first().and_then(|q| q.value.cooked.map(|s| s.to_string())).filter(|s| !s.is_empty())
                    }
                    _ => None,
                };
                let line = 1 + text.as_bytes()[..dyn_imp.span.start as usize].iter().filter(|&&b| b == b'\n').count() as u32;
                facts.dynamic_loads.push(DynamicLoad {
                    line,
                    func: String::new(),
                    owner: String::new(),
                    what: "import()".into(),
                    prefix,
                });
            }
        }
    }

    // 3. TypeScript `typeof import('...')` / `import('...').Type` (`TSImportType`), CommonJS / TS `require('...')`,
    //    and Vitest `vi.importActual('...')`.
    let tokens = &ret.tokens;
    for i in 0..tokens.len() {
        let tok = &tokens[i];
        match tok.kind() {
            Kind::Import if !dyn_starts.contains(&tok.start()) && tokens.get(i + 1).is_some_and(|t| t.kind() == Kind::LParen) => {
                if let Some(spec) = tokens.get(i + 2).and_then(|t| decode_str_token(&allocator, text, t)) {
                    push_spec(spec);
                }
            }
            Kind::Require
                if !matches!(
                    i.checked_sub(1).and_then(|p| tokens.get(p)).map(Token::kind),
                    Some(Kind::Dot | Kind::QuestionDot | Kind::Function)
                ) && tokens.get(i + 1).is_some_and(|t| t.kind() == Kind::LParen)
                    && tokens.get(i + 3).is_some_and(|t| t.kind() == Kind::RParen) =>
            {
                if let Some(spec) = tokens.get(i + 2).and_then(|t| decode_str_token(&allocator, text, t)) {
                    push_spec(spec);
                }
            }
            Kind::Ident
                if text.get(tok.start() as usize..tok.end() as usize) == Some("vi")
                    && tokens.get(i + 1).is_some_and(|t| t.kind() == Kind::Dot)
                    && tokens
                        .get(i + 2)
                        .is_some_and(|t| text.get(t.start() as usize..t.end() as usize) == Some("importActual"))
                    && tokens.get(i + 3).is_some_and(|t| t.kind() == Kind::LParen) =>
            {
                if let Some(spec) = tokens.get(i + 4).and_then(|t| decode_str_token(&allocator, text, t)) {
                    push_spec(spec);
                }
            }
            _ => {}
        }
    }

    facts
}

/// Strip `//` line comments, `/* ... */` block comments, and trailing commas outside string literals so JSONC
/// files (`tsconfig.json`, `jsconfig.json`) parse cleanly with `serde_json`.
pub fn strip_jsonc(input: &str) -> String {
    let input = input.strip_prefix('\u{feff}').unwrap_or(input);
    let mut no_comments = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if in_string {
            no_comments.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match (ch, chars.peek().copied()) {
            ('"', _) => {
                in_string = true;
                no_comments.push(ch);
            }
            ('/', Some('/')) => {
                chars.next();
                for c in chars.by_ref() {
                    if c == '\n' {
                        no_comments.push('\n');
                        break;
                    }
                }
            }
            ('/', Some('*')) => {
                chars.next();
                while let Some(c) = chars.next() {
                    if c == '*' && chars.peek() == Some(&'/') {
                        chars.next();
                        no_comments.push(' ');
                        break;
                    }
                    if c == '\n' {
                        no_comments.push('\n');
                    }
                }
            }
            _ => no_comments.push(ch),
        }
    }

    // Second pass: drop trailing commas whose next non-whitespace token is `}` or `]`.
    let bytes = no_comments.as_bytes();
    let mut out = String::with_capacity(no_comments.len());
    let mut in_str = false;
    let mut esc = false;
    let mut idx = 0usize;
    while idx < bytes.len() {
        let ch = no_comments[idx..].chars().next().expect("valid char boundary");
        let next_idx = idx + ch.len_utf8();
        if in_str {
            out.push(ch);
            if esc {
                esc = false;
            } else if ch == '\\' {
                esc = true;
            } else if ch == '"' {
                in_str = false;
            }
        } else if ch == '"' {
            in_str = true;
            out.push(ch);
        } else if ch == ',' {
            let rest = no_comments[next_idx..].trim_start();
            if !rest.starts_with('}') && !rest.starts_with(']') {
                out.push(ch);
            }
        } else {
            out.push(ch);
        }
        idx = next_idx;
    }
    out
}

fn extract_tsconfig(source: &[u8]) -> FileFacts {
    let Ok(text) = std::str::from_utf8(source) else {
        return FileFacts { parse_error: true, ..FileFacts::default() };
    };
    let cleaned = strip_jsonc(text);
    let Ok(val) = serde_json::from_str::<serde_json::Value>(&cleaned) else {
        return FileFacts::default();
    };
    let mut cfg = TsConfigFacts::default();
    match val.get("extends") {
        Some(serde_json::Value::String(s)) => cfg.extends.push(s.clone()),
        Some(serde_json::Value::Array(arr)) => {
            cfg.extends.extend(arr.iter().filter_map(serde_json::Value::as_str).map(str::to_owned));
        }
        _ => {}
    }
    if let Some(refs) = val.get("references").and_then(serde_json::Value::as_array) {
        for r in refs {
            if let Some(p) = r.get("path").and_then(serde_json::Value::as_str) {
                cfg.references.push(p.to_owned());
            }
        }
    }
    if let Some(co) = val.get("compilerOptions").and_then(serde_json::Value::as_object) {
        if let Some(base) = co.get("baseUrl").and_then(serde_json::Value::as_str) {
            cfg.base_url = Some(base.to_owned());
        }
        if let Some(paths) = co.get("paths").and_then(serde_json::Value::as_object) {
            for (pattern, targets) in paths {
                if let Some(arr) = targets.as_array() {
                    let list: Vec<String> = arr.iter().filter_map(serde_json::Value::as_str).map(str::to_owned).collect();
                    if !list.is_empty() {
                        cfg.paths.push((pattern.clone(), list));
                    }
                }
            }
        }
    }
    FileFacts { tsconfig: Some(cfg), ..FileFacts::default() }
}

fn collect_export_strings(val: &serde_json::Value, out: &mut Vec<String>) {
    match val {
        serde_json::Value::String(s) if s.starts_with("./") || !s.contains(':') => {
            let normalized = if s.starts_with('.') { s.clone() } else { format!("./{s}") };
            if !out.contains(&normalized) {
                out.push(normalized);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_export_strings(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            // Prefer runtime/source conditions alongside `types` so source mapping finds `.ts` / `.mjs`.
            for (_, v) in map {
                collect_export_strings(v, out);
            }
        }
        _ => {}
    }
}

fn extract_package_json(source: &[u8]) -> FileFacts {
    let source = source.strip_prefix(b"\xef\xbb\xbf").unwrap_or(source);
    let Ok(text) = std::str::from_utf8(source) else {
        return FileFacts { parse_error: true, ..FileFacts::default() };
    };
    let Ok(val) = serde_json::from_str::<serde_json::Value>(text) else {
        return FileFacts::default();
    };
    let Some(obj) = val.as_object() else {
        return FileFacts::default();
    };
    let name = obj.get("name").and_then(serde_json::Value::as_str).filter(|s| !s.is_empty()).map(str::to_owned);
    let mut export_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if let Some(exports) = obj.get("exports") {
        match exports {
            serde_json::Value::Object(map) if map.keys().any(|k| k.starts_with('.')) => {
                for (subpath, target_val) in map {
                    if subpath.starts_with('.') {
                        collect_export_strings(target_val, export_map.entry(subpath.clone()).or_default());
                    }
                }
            }
            other => {
                collect_export_strings(other, export_map.entry(".".to_owned()).or_default());
            }
        }
    }
    for key in ["source", "module", "main", "types", "typings"] {
        if let Some(s) = obj.get(key).and_then(serde_json::Value::as_str) {
            let normalized = if s.starts_with('.') { s.to_owned() } else { format!("./{s}") };
            let root_slot = export_map.entry(".".to_owned()).or_default();
            if !root_slot.contains(&normalized) {
                root_slot.push(normalized);
            }
        }
    }
    let pkg = PackageJsonFacts { name, exports: export_map.into_iter().collect() };
    FileFacts { package_json: Some(pkg), ..FileFacts::default() }
}

fn parent_dir(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(dir, _)| dir)
}

fn join_dir(base: &str, tail: &str) -> String {
    match (base.is_empty(), tail.is_empty()) {
        (true, _) => tail.to_owned(),
        (_, true) => base.to_owned(),
        _ => format!("{base}/{tail}"),
    }
}

/// Candidate tree paths for a normalized TypeScript/JavaScript target path.
///
/// Unlike `Path::extension()`, dot-in-stem filenames (`routeTree.gen`, `BuildSwarmCard.parts`,
/// `ForumThreadView.types`, `company.schema`) still receive `.ts`, `.tsx`, etc. appended via string
/// concatenation, while explicit `.js`/`.mjs`/`.cjs`/`.jsx` ESM specifiers remap to their TypeScript sources.
pub fn probe_ts_path(base: &str) -> Vec<String> {
    let mut candidates = vec![base.to_owned()];
    if let Some(stem) = base.strip_suffix(".js") {
        for ext in ["ts", "tsx", "d.ts", "jsx"] {
            candidates.push(format!("{stem}.{ext}"));
        }
    } else if let Some(stem) = base.strip_suffix(".jsx") {
        for ext in ["tsx", "ts"] {
            candidates.push(format!("{stem}.{ext}"));
        }
    } else if let Some(stem) = base.strip_suffix(".mjs") {
        for ext in ["mts", "d.mts", "ts"] {
            candidates.push(format!("{stem}.{ext}"));
        }
    } else if let Some(stem) = base.strip_suffix(".cjs") {
        for ext in ["cts", "d.cts", "ts"] {
            candidates.push(format!("{stem}.{ext}"));
        }
    }

    let file_name = base.rsplit('/').next().unwrap_or(base);
    let has_known_ext = file_name.rsplit_once('.').is_some_and(|(_, ext)| KNOWN_MODULE_EXTS.contains(&ext))
        || file_name.ends_with(".d.ts")
        || file_name.ends_with(".d.mts")
        || file_name.ends_with(".d.cts");
    if !has_known_ext {
        for ext in PROBE_EXTS {
            candidates.push(format!("{base}.{ext}"));
            candidates.push(format!("{base}/index.{ext}"));
        }
        candidates.push(format!("{base}.json"));
    }
    candidates
}

#[derive(Debug, Clone)]
struct PathAliasRule {
    pattern: String,
    base_dir: String,
    targets: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct ResolvedTsConfig {
    files: Vec<u32>,
    rules: Vec<PathAliasRule>,
}

#[derive(Debug, Clone)]
struct WorkspacePkg {
    pkg_json_idx: u32,
    dir: String,
    exports: Vec<(String, Vec<String>)>,
}

#[derive(Debug, Default)]
pub struct TsOutcome {
    pub targets: Vec<u32>,
    pub reads: Vec<u32>,
    pub unresolved: bool,
}

/// Precomputed TypeScript/JavaScript project layout for a single tree: `tsconfig` path maps, workspace
/// `package.json` packages, and nearest lockfiles.
#[derive(Debug, Default)]
pub struct TsProjectIndex {
    dir_configs: HashMap<String, ResolvedTsConfig>,
    explicit_rules: Vec<PathAliasRule>,
    workspaces: HashMap<String, WorkspacePkg>,
    lockfiles_by_dir: HashMap<String, u32>,
}

enum AliasMatch<'a> {
    TypeShimOnly,
    Matched { capture: String, strip_wildcard_dir: bool, rule: &'a PathAliasRule },
}

fn match_alias_rules<'a>(spec: &str, rules: &'a [PathAliasRule]) -> Option<AliasMatch<'a>> {
    let mut best: Option<(usize, String, bool, &'a PathAliasRule)> = None;
    for rule in rules {
        let (score, capture, strip_dir) = match rule.pattern.split_once('*') {
            None if rule.pattern == spec => (usize::MAX, String::new(), false),
            None => continue,
            Some((pre, post)) if spec.len() >= pre.len() + post.len() && spec.starts_with(pre) && spec.ends_with(post) => {
                (pre.len() + post.len() + 2, spec[pre.len()..spec.len() - post.len()].to_owned(), false)
            }
            // Bundler directory-alias parity: `@/aiAgents/chat/*` -> `./src/features/aiAgents/chat/*` also resolves
            // bare `@/aiAgents/chat` before falling back to a shorter `@/*` wildcard.
            Some((pre, "")) if pre.ends_with('/') && pre.trim_end_matches('/') == spec => (pre.len() + 1, String::new(), true),
            Some(_) => continue,
        };
        if best.as_ref().is_none_or(|(s, ..)| score > *s) {
            best = Some((score, capture, strip_dir, rule));
        }
    }
    let (_, capture, strip_wildcard_dir, rule) = best?;
    let has_non_node_modules = rule.targets.iter().any(|t| !t.split('/').any(|seg| seg == "node_modules"));
    if !has_non_node_modules {
        return Some(AliasMatch::TypeShimOnly);
    }
    Some(AliasMatch::Matched { capture, strip_wildcard_dir, rule })
}

impl TsProjectIndex {
    pub fn build(all: &AllFacts, config: &ImportConfig) -> Self {
        let mut raw_tsconfigs: HashMap<String, (u32, &TsConfigFacts)> = HashMap::new();
        let mut tsconfig_dirs: HashSet<String> = HashSet::new();
        let mut workspaces: HashMap<String, WorkspacePkg> = HashMap::new();
        let mut lockfile_candidates: HashMap<String, (usize, u32)> = HashMap::new();

        for (index, file) in all.files.iter().enumerate() {
            let idx = index as u32;
            let name = file.path.rsplit('/').next().unwrap_or(&file.path);
            if let Some(prio) = LOCKFILES.iter().position(|&lk| lk == name) {
                let dir = parent_dir(&file.path).to_owned();
                if lockfile_candidates.get(&dir).is_none_or(|(best, _)| prio < *best) {
                    lockfile_candidates.insert(dir, (prio, idx));
                }
            }
            match file.kind {
                Some(FileKind::TsConfig) => {
                    if let Some(cfg) = file.facts.as_deref().and_then(|f| f.tsconfig.as_ref()) {
                        tsconfig_dirs.insert(parent_dir(&file.path).to_owned());
                        raw_tsconfigs.insert(file.path.clone(), (idx, cfg));
                    }
                }
                Some(FileKind::PackageJson) => {
                    if let Some(pkg) = file.facts.as_deref().and_then(|f| f.package_json.as_ref()) {
                        if let Some(pkg_name) = &pkg.name {
                            workspaces.insert(
                                pkg_name.clone(),
                                WorkspacePkg {
                                    pkg_json_idx: idx,
                                    dir: parent_dir(&file.path).to_owned(),
                                    exports: pkg.exports.clone(),
                                },
                            );
                        }
                    }
                }
                _ => {}
            }
        }

        fn resolve_one(
            path: &str,
            raw: &HashMap<String, (u32, &TsConfigFacts)>,
            stack: &mut Vec<String>,
        ) -> Option<(ResolvedTsConfig, Option<String>)> {
            if stack.len() > 8 || stack.iter().any(|s| s == path) {
                return None;
            }
            let &(idx, cfg) = raw.get(path)?;
            let dir = parent_dir(path);
            stack.push(path.to_owned());

            let mut files = vec![idx];
            let mut inherited_base: Option<String> = None;
            let mut rule_map: Vec<PathAliasRule> = Vec::new();

            for ext in &cfg.extends {
                if !(ext.starts_with("./") || ext.starts_with("../")) {
                    continue;
                }
                let Some(dest) = link_destination(dir, ext) else { continue };
                let candidates = [dest.clone(), format!("{dest}.json"), join_dir(&dest, "tsconfig.json")];
                if let Some((parent_resolved, parent_base)) = candidates.iter().find_map(|cand| resolve_one(cand, raw, stack)) {
                    for f in parent_resolved.files {
                        if !files.contains(&f) {
                            files.push(f);
                        }
                    }
                    if parent_base.is_some() {
                        inherited_base = parent_base;
                    }
                    for r in parent_resolved.rules {
                        if let Some(slot) = rule_map.iter_mut().find(|existing| existing.pattern == r.pattern) {
                            *slot = r;
                        } else {
                            rule_map.push(r);
                        }
                    }
                }
            }

            let own_base = cfg.base_url.as_deref().and_then(|b| link_destination(dir, b));
            let effective_base =
                own_base.clone().or_else(|| if !cfg.paths.is_empty() { Some(dir.to_owned()) } else { inherited_base });
            let paths_anchor = effective_base.clone().unwrap_or_else(|| dir.to_owned());
            for (pattern, targets) in &cfg.paths {
                let rule = PathAliasRule { pattern: pattern.clone(), base_dir: paths_anchor.clone(), targets: targets.clone() };
                if let Some(slot) = rule_map.iter_mut().find(|existing| existing.pattern == *pattern) {
                    *slot = rule;
                } else {
                    rule_map.push(rule);
                }
            }

            stack.pop();
            Some((ResolvedTsConfig { files, rules: rule_map }, effective_base))
        }

        let mut dir_configs = HashMap::new();
        for dir in tsconfig_dirs {
            let mut merged = ResolvedTsConfig::default();
            let mut primary_names = vec![
                join_dir(&dir, "tsconfig.json"),
                join_dir(&dir, "tsconfig.app.json"),
                join_dir(&dir, "tsconfig.vitest.json"),
                join_dir(&dir, "jsconfig.json"),
            ];
            // Solution-style `tsconfig.json` often delegates to `./tsconfig.app.json` via `references`.
            if let Some((_, root_cfg)) = raw_tsconfigs.get(&primary_names[0]) {
                for r in &root_cfg.references {
                    if let Some(dest) = link_destination(&dir, r) {
                        for cand in [dest.clone(), join_dir(&dest, "tsconfig.json")] {
                            if !primary_names.contains(&cand) {
                                primary_names.push(cand);
                            }
                        }
                    }
                }
            }
            for cfg_path in primary_names {
                let mut stack = Vec::new();
                if let Some((resolved, _)) = resolve_one(&cfg_path, &raw_tsconfigs, &mut stack) {
                    if resolved.rules.is_empty() {
                        continue;
                    }
                    for f in resolved.files {
                        if !merged.files.contains(&f) {
                            merged.files.push(f);
                        }
                    }
                    for rule in resolved.rules {
                        if !merged.rules.iter().any(|r| r.pattern == rule.pattern) {
                            merged.rules.push(rule);
                        }
                    }
                }
            }
            if !merged.rules.is_empty() {
                dir_configs.insert(dir, merged);
            }
        }

        let explicit_base = link_destination("", &config.ts_base_url).unwrap_or_default();
        let explicit_rules = config
            .ts_paths
            .iter()
            .map(|(pattern, targets)| PathAliasRule {
                pattern: pattern.clone(),
                base_dir: explicit_base.clone(),
                targets: targets.clone(),
            })
            .collect();

        let lockfiles_by_dir = lockfile_candidates.into_iter().map(|(dir, (_, idx))| (dir, idx)).collect();
        Self { dir_configs, explicit_rules, workspaces, lockfiles_by_dir }
    }

    fn nearest_lockfile(&self, importer: &str) -> Option<u32> {
        let mut dir = parent_dir(importer);
        loop {
            if let Some(&idx) = self.lockfiles_by_dir.get(dir) {
                return Some(idx);
            }
            if dir.is_empty() {
                return None;
            }
            dir = parent_dir(dir);
        }
    }

    fn resolve_alias_rule(
        capture: &str,
        strip_wildcard_dir: bool,
        rule: &PathAliasRule,
        cfg_files: &[u32],
        lookup: &mut impl FnMut(&str, &mut Vec<u32>),
    ) -> TsOutcome {
        let mut out = TsOutcome { reads: cfg_files.to_vec(), ..TsOutcome::default() };
        let mut any_valid_dest = false;
        for raw_target in &rule.targets {
            if raw_target.split('/').any(|seg| seg == "node_modules") {
                continue;
            }
            let substituted = if strip_wildcard_dir {
                raw_target.strip_suffix("/*").unwrap_or(raw_target).to_owned()
            } else {
                raw_target.replacen('*', capture, 1)
            };
            let joined = join_dir(&rule.base_dir, &substituted);
            let Some(dest) = link_destination("", &joined) else {
                continue;
            };
            any_valid_dest = true;
            for cand in probe_ts_path(&dest) {
                lookup(&cand, &mut out.targets);
            }
        }
        out.unresolved = !any_valid_dest || out.targets.is_empty();
        out
    }

    fn resolve_workspace(&self, spec: &str, lookup: &mut impl FnMut(&str, &mut Vec<u32>)) -> Option<TsOutcome> {
        let (pkg, subpath) = if let Some(pkg) = self.workspaces.get(spec) {
            (pkg, ".".to_owned())
        } else {
            let mut matched = None;
            for (name, pkg) in &self.workspaces {
                if let Some(rest) = spec.strip_prefix(name.as_str()).and_then(|r| r.strip_prefix('/')) {
                    matched = Some((pkg, format!("./{rest}")));
                    break;
                }
            }
            matched?
        };

        let mut out = TsOutcome { reads: vec![pkg.pkg_json_idx], ..TsOutcome::default() };
        let mut candidate_rel_paths: Vec<String> = Vec::new();
        for (pattern, targets) in &pkg.exports {
            if *pattern == subpath {
                candidate_rel_paths.extend(targets.iter().cloned());
            } else if let Some((pre, post)) = pattern.split_once('*') {
                if subpath.len() >= pre.len() + post.len() && subpath.starts_with(pre) && subpath.ends_with(post) {
                    let cap = &subpath[pre.len()..subpath.len() - post.len()];
                    candidate_rel_paths.extend(targets.iter().map(|t| t.replacen('*', cap, 1)));
                }
            }
        }
        // Source-first fallbacks for monorepo packages whose `exports`/`main` point into untracked `dist/`.
        let mut expanded: Vec<String> = Vec::new();
        for rel in &candidate_rel_paths {
            expanded.push(rel.clone());
            let trimmed = rel.strip_prefix("./").unwrap_or(rel);
            for out_dir in ["dist/", "build/", "out/"] {
                if let Some(rest) = trimmed.strip_prefix(out_dir) {
                    let rest = rest.strip_suffix(".d.ts").map_or(rest.to_owned(), |s| format!("{s}.ts"));
                    expanded.push(format!("./src/{rest}"));
                    expanded.push(format!("./{rest}"));
                }
            }
        }
        if subpath == "." {
            expanded.extend(["./src/index".to_owned(), "./index".to_owned()]);
        } else if let Some(tail) = subpath.strip_prefix("./") {
            expanded.extend([format!("./src/{tail}"), format!("./lib/{tail}"), format!("./{tail}")]);
        }

        for rel in expanded {
            if let Some(dest) = link_destination(&pkg.dir, &rel) {
                for cand in probe_ts_path(&dest) {
                    lookup(&cand, &mut out.targets);
                }
            }
        }
        if out.targets.is_empty() {
            return None;
        }
        Some(out)
    }

    pub fn resolve_ts(
        &self,
        _kind: FileKind,
        importer: &str,
        raw_name: &str,
        config: &ImportConfig,
        mut lookup: impl FnMut(&str, &mut Vec<u32>),
    ) -> TsOutcome {
        let spec = raw_name.split(['?', '#']).next().unwrap_or(raw_name);
        if spec.is_empty() {
            return TsOutcome { unresolved: true, ..TsOutcome::default() };
        }

        // 1. Relative path (`./...`, `../...`, `.`, `..`).
        if spec == "." || spec == ".." || spec.starts_with("./") || spec.starts_with("../") {
            let Some(dest) = link_destination(parent_dir(importer), spec) else {
                return TsOutcome { unresolved: true, ..TsOutcome::default() };
            };
            let mut out = TsOutcome::default();
            for cand in probe_ts_path(&dest) {
                lookup(&cand, &mut out.targets);
            }
            out.unresolved = out.targets.is_empty();
            return out;
        }

        // 2. Explicit `ImportConfig.ts_paths` overrides, then nearest ancestor `tsconfig` path aliases.
        let mut shim_only = false;
        if !self.explicit_rules.is_empty() {
            match match_alias_rules(spec, &self.explicit_rules) {
                Some(AliasMatch::Matched { capture, strip_wildcard_dir, rule }) => {
                    return Self::resolve_alias_rule(&capture, strip_wildcard_dir, rule, &[], &mut lookup);
                }
                Some(AliasMatch::TypeShimOnly) => shim_only = true,
                None => {}
            }
        }
        if !shim_only {
            let mut dir = parent_dir(importer);
            loop {
                if let Some(cfg) = self.dir_configs.get(dir) {
                    match match_alias_rules(spec, &cfg.rules) {
                        Some(AliasMatch::Matched { capture, strip_wildcard_dir, rule }) => {
                            return Self::resolve_alias_rule(&capture, strip_wildcard_dir, rule, &cfg.files, &mut lookup);
                        }
                        Some(AliasMatch::TypeShimOnly) => break,
                        None => {}
                    }
                }
                if dir.is_empty() {
                    break;
                }
                dir = parent_dir(dir);
            }
        }

        // 3. Monorepo workspace packages (`@scope/pkg`, `@scope/pkg/subpath`).
        if let Some(ws_outcome) = self.resolve_workspace(spec, &mut lookup) {
            return ws_outcome;
        }

        // 4. Node.js / runtime built-in modules (`node:*`, `fs`, `path`, `crypto`, ...): zero repo file dependencies.
        if raw_name.starts_with("node:") || raw_name.starts_with("bun:") || raw_name.starts_with("cloudflare:") {
            return TsOutcome::default();
        }
        let head = spec.split('/').next().unwrap_or(spec);
        if !spec.starts_with('@') && NODE_BUILTINS.binary_search(&head).is_ok() {
            return TsOutcome::default();
        }

        // 5. Bare external packages vs unconfigured path aliases.
        if config.bare_imports == BareImports::Widen {
            return TsOutcome { unresolved: true, ..TsOutcome::default() };
        }
        if spec.starts_with('/')
            || spec.starts_with("@/")
            || spec.starts_with("~/")
            || spec.starts_with('#')
            || spec.split('/').any(|seg| seg == "..")
        {
            return TsOutcome { unresolved: true, ..TsOutcome::default() };
        }
        let external_protocol = raw_name.starts_with("https://")
            || raw_name.starts_with("http://")
            || raw_name.starts_with("npm:")
            || raw_name.starts_with("jsr:")
            || raw_name.starts_with("virtual:");
        if !external_protocol && !is_valid_bare_package(spec) {
            return TsOutcome { unresolved: true, ..TsOutcome::default() };
        }

        let mut out = TsOutcome::default();
        if let Some(lockfile) = self.nearest_lockfile(importer) {
            out.reads.push(lockfile);
        }
        out
    }
}

fn is_valid_bare_package(spec: &str) -> bool {
    if let Some(scoped) = spec.strip_prefix('@') {
        let Some((scope, rest)) = scoped.split_once('/') else {
            return false;
        };
        let pkg = rest.split('/').next().unwrap_or("");
        !scope.is_empty() && !pkg.is_empty() && scope != "." && pkg != "."
    } else {
        !spec.is_empty() && !spec.starts_with('.')
    }
}

pub fn resolve(kind: FileKind, importer: &str, name: &str, config: &ImportConfig) -> Vec<String> {
    let roots = &config.roots;
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
    let spec = name.split(['?', '#']).next().unwrap_or(name);
    if !(spec.starts_with("./") || spec.starts_with("../")) {
        return Vec::new();
    }
    let Some(path) = link_destination(dir.to_str().unwrap_or(""), spec) else { return Vec::new() };
    probe_ts_path(&path)
}

#[cfg(test)]
mod tests {
    use crate::{
        imports::{cones, Cause},
        AllFacts, BareImports, ImportConfig, ImportGraph,
    };
    use landd_core::Digest32;

    fn closure(files: &[(&str, &str)], root: &str, expected: &[&str]) {
        let all = AllFacts::from_sources(files);
        let config = ImportConfig { tests: vec![root.into()], always: vec![], ..ImportConfig::default() };
        let graph = ImportGraph::build(&all, &config);
        let result = cones(&all, &graph, &config, &Digest32::blake3(b"runner"));
        assert!(!result[0].widened, "{:?}", result[0].causes);
        assert_eq!(result[0].input_paths(&all).collect::<Vec<_>>(), expected);
    }

    fn closure_with(files: &[(&str, &str)], config: ImportConfig, root: &str) -> (bool, Vec<String>, Vec<Cause>) {
        let all = AllFacts::from_sources(files);
        let config = ImportConfig { tests: vec![root.into()], always: vec![], ..config };
        let graph = ImportGraph::build(&all, &config);
        let result = cones(&all, &graph, &config, &Digest32::blake3(b"runner"));
        let causes = result[0].causes.iter().map(|(_, c)| *c).collect();
        (result[0].widened, result[0].input_paths(&all).map(str::to_owned).collect(), causes)
    }

    fn paths(entries: &[(&str, &[&str])]) -> ImportConfig {
        ImportConfig {
            ts_paths: entries.iter().map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect())).collect(),
            ..ImportConfig::default()
        }
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

    #[test]
    fn tsx_jsx_generics_entities_and_type_imports_parse_without_widening() {
        closure(
            &[
                (
                    "src/View.test.tsx",
                    "import { render } from '@testing-library/react'\n\
                     import type { Item } from './View.types'\n\
                     import { View } from './View'\n\
                     const actual = async <T,>(fn: () => Promise<T>) => fn<typeof import('./helper')>()\n\
                     export function Wrap() { return <View label=\"History & compare\" /> }\n",
                ),
                ("src/View.tsx", "export * from './reexport'\nexport const View = ({ label }: { label: string }) => <span>{label} & more</span>\n"),
                ("src/View.types.ts", "export interface Item { id: string\n  in: string }\n"),
                ("src/reexport.ts", "export type * from './deep.js'\n"),
                ("src/deep.ts", "import type { Ambient } from './ambient.mjs'\nexport type Deep = Ambient\n"),
                ("src/ambient.d.mts", "export const SCHEMA: 'v1'\nexport type Ambient = number\nexport function check(): void\n"),
                ("src/helper.jsx", "export const H = () => <div>A & B</div>\n"),
                ("src/untouched.tsx", "export const Other = () => <div />\n"),
            ],
            "src/View.test.tsx",
            &[
                "src/View.test.tsx",
                "src/View.tsx",
                "src/View.types.ts",
                "src/ambient.d.mts",
                "src/deep.ts",
                "src/helper.jsx",
                "src/reexport.ts",
            ],
        );
    }

    #[test]
    fn auto_discovered_jsonc_tsconfig_and_extends_resolve_aliases_and_dots_in_stem() {
        let tsconfig = r#"{
            // Schema URL inside a string must survive JSONC comment stripping:
            "$schema": "https://json.schemastore.org/tsconfig",
            /* Block comment before compilerOptions */
            "compilerOptions": {
                "baseUrl": ".",
                "paths": {
                    "react": ["./node_modules/@types/react"],
                    "react/*": ["./node_modules/@types/react/*"],
                    "@/*": ["./src/*"],
                    "@/aiAgents/chat/*": ["./src/features/aiAgents/chat/*"],
                    "@/shared/*": ["./shared/*"],
                },
            },
        }"#;
        let vitest_tsconfig = r#"{
            "extends": "./tsconfig.json",
            "compilerOptions": { "noEmit": true }
        }"#;
        closure(
            &[
                ("tsconfig.json", tsconfig),
                ("tsconfig.vitest.json", vitest_tsconfig),
                (
                    "src/app.test.tsx",
                    "import React from 'react'\n\
                     import 'react/jsx-runtime'\n\
                     import { card } from './BuildSwarmCard.parts'\n\
                     import { tree } from '@/routes/routeTree.gen'\n\
                     import { chat } from '@/aiAgents/chat/session'\n\
                     import { sh } from '@/shared/contract.schema'\n",
                ),
                ("src/BuildSwarmCard.parts.tsx", "export const card = 1\n"),
                ("src/routes/routeTree.gen.ts", "export const tree = 2\n"),
                ("src/features/aiAgents/chat/session.ts", "export const chat = 3\n"),
                ("shared/contract.schema.ts", "export const sh = 4\n"),
                ("src/shared/contract.schema.ts", "export const wrong = 5\n"),
                ("src/unrelated.ts", "export const nope = 6\n"),
            ],
            "src/app.test.tsx",
            &[
                "shared/contract.schema.ts",
                "src/BuildSwarmCard.parts.tsx",
                "src/app.test.tsx",
                "src/features/aiAgents/chat/session.ts",
                "src/routes/routeTree.gen.ts",
                "tsconfig.json",
                "tsconfig.vitest.json",
            ],
        );

        // Solution-style `tsconfig.json` referencing `./tsconfig.app.json`, which extends `./tsconfig.base.json`.
        closure(
            &[
                ("tsconfig.json", r#"{"files": [], "references": [{"path": "./tsconfig.app.json"}]}"#),
                ("tsconfig.app.json", r#"{"extends": "./tsconfig.base", "compilerOptions": {"noEmit": true}}"#),
                ("tsconfig.base.json", r#"{"compilerOptions": {"paths": {"@/*": ["./src/*"]}}}"#),
                ("src/leaf.test.ts", "import { x } from '@/x'\n"),
                ("src/x.ts", "export const x = 1\n"),
                ("src/y.ts", "export const y = 2\n"),
            ],
            "src/leaf.test.ts",
            &["src/leaf.test.ts", "src/x.ts", "tsconfig.app.json", "tsconfig.base.json"],
        );
    }

    #[test]
    fn bare_packages_bind_to_nearest_lockfile_while_node_builtins_add_nothing() {
        let base = [
            ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
            ("src/ui.test.tsx", "import React from 'react'; import { z } from 'zod'; import { util } from './util'\n"),
            ("src/pure.test.ts", "import fs from 'node:fs'; import path from 'path'; import { util } from './util'\n"),
            ("src/util.ts", "export const util = 1\n"),
            ("src/other.ts", "export const other = 2\n"),
        ];
        closure(&base, "src/ui.test.tsx", &["pnpm-lock.yaml", "src/ui.test.tsx", "src/util.ts"]);
        closure(&base, "src/pure.test.ts", &["src/pure.test.ts", "src/util.ts"]);

        // Editing the lockfile moves `ui.test.tsx`'s cone digest while leaving `pure.test.ts` untouched;
        // editing `src/other.ts` leaves both untouched.
        let config = ImportConfig {
            tests: vec!["src/*.test.ts".into(), "src/*.test.tsx".into()],
            always: vec![],
            ..ImportConfig::default()
        };
        let ctx = Digest32::blake3(b"runner");
        let run = |files: &[(&str, &str)]| {
            let all = AllFacts::from_sources(files);
            let g = ImportGraph::build(&all, &config);
            cones(&all, &g, &config, &ctx)
        };
        let c0 = run(&base);
        let mut edited_other = base;
        edited_other[4].1 = "export const other = 99\n";
        let c_other = run(&edited_other);
        assert_eq!(c0[0].digest, c_other[0].digest);
        assert_eq!(c0[1].digest, c_other[1].digest);

        let mut edited_lock = base;
        edited_lock[0].1 = "lockfileVersion: '9.0'\npackages: {}\n";
        let c_lock = run(&edited_lock);
        assert_eq!(c0[0].path, "src/pure.test.ts");
        assert_eq!(c0[0].digest, c_lock[0].digest, "node:* built-ins must not invalidate on lockfile edit");
        assert_eq!(c0[1].path, "src/ui.test.tsx");
        assert_ne!(c0[1].digest, c_lock[1].digest, "npm package consumer must invalidate on lockfile edit");

        let widen = ImportConfig { bare_imports: BareImports::Widen, ..ImportConfig::default() };
        assert!(closure_with(&base, widen, "src/ui.test.tsx").0);
    }

    #[test]
    fn monorepo_workspace_packages_resolve_through_exports_and_dist_to_src() {
        closure(
            &[
                ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
                (
                    "packages/artifacts/package.json",
                    r#"{"name":"@acme/artifacts","main":"./dist/index.js","exports":{".":{"types":"./dist/index.d.ts","import":"./dist/index.js"}}}"#,
                ),
                ("packages/artifacts/src/index.ts", "export { Claim } from './claim'\n"),
                ("packages/artifacts/src/claim.ts", "export interface Claim { id: string }\n"),
                (
                    "packages/broker/package.json",
                    r#"{"name":"@acme/broker","exports":{".":"./lib/index.mjs","./authority":"./lib/authority.mjs"}}"#,
                ),
                ("packages/broker/lib/authority.mjs", "export const allow = true\n"),
                ("packages/broker/lib/unused.mjs", "export const unused = false\n"),
                (
                    "src/check.test.ts",
                    "import type { Claim } from '@acme/artifacts'\nimport { allow } from '@acme/broker/authority'\n",
                ),
            ],
            "src/check.test.ts",
            &[
                "packages/artifacts/package.json",
                "packages/artifacts/src/claim.ts",
                "packages/artifacts/src/index.ts",
                "packages/broker/lib/authority.mjs",
                "packages/broker/package.json",
                "src/check.test.ts",
            ],
        );
    }

    #[test]
    fn tooth_missing_targets_unconfigured_aliases_dynamic_imports_and_syntax_errors_widen() {
        let config = paths(&[("@/*", &["./src/*"])]);
        let (w_missing, _, c_missing) = closure_with(&[("a.test.ts", "import '@/nope'")], config.clone(), "a.test.ts");
        assert!(w_missing && c_missing == [Cause::UnresolvedLoad]);

        let (w_unmapped, _, c_unmapped) =
            closure_with(&[("a.test.ts", "import '@/lib/x'"), ("src/lib/x.ts", "")], ImportConfig::default(), "a.test.ts");
        assert!(w_unmapped && c_unmapped == [Cause::UnresolvedLoad]);

        let all_dyn = AllFacts::from_sources(&[("a.test.ts", "const n = './x'; import(n)")]);
        let dyn_facts = all_dyn.find("a.test.ts").unwrap().facts.as_ref().unwrap();
        assert!(!dyn_facts.parse_error, "computed import(n) is a DynamicLoad, not a syntax error");
        assert_eq!(dyn_facts.dynamic_loads.len(), 1);
        let (w_dyn, _, c_dyn) = closure_with(&[("a.test.ts", "const n = './x'; import(n)")], config.clone(), "a.test.ts");
        assert!(w_dyn && c_dyn == [Cause::DynamicLoad]);

        assert!(closure_with(&[("a.test.ts", "import '../../outside'")], config.clone(), "a.test.ts").0);
        assert!(closure_with(&[("a.test.ts", "import '@/../../outside'")], config.clone(), "a.test.ts").0);

        let (w_err, _, c_err) = closure_with(&[("a.test.ts", "const = ;")], config, "a.test.ts");
        assert!(w_err && c_err == [Cause::ParseError]);
    }
}
