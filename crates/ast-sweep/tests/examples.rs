//! The example rule pack in the repository parses.

use ast_sweep::{RuleKind, RulePack};

#[test]
fn example_rule_pack_parses_and_covers_every_rule_kind() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/fleet-gen3.rules.toml")).unwrap();
    let pack = RulePack::from_toml(&text).unwrap();
    let kinds: Vec<RuleKind> = pack.rule.iter().map(|r| r.kind).collect();
    for kind in [
        RuleKind::NoTrackedBytecode,
        RuleKind::NoBarePythonRecipe,
        RuleKind::FlockBounded,
        RuleKind::AtomicReplaceOwner,
        RuleKind::UncataloguedSettingsKeys,
        RuleKind::ForbiddenSymbolOrCall,
        RuleKind::SingleOwnerPattern,
        RuleKind::PythonImportGraph,
    ] {
        assert!(kinds.contains(&kind), "{kind:?}");
    }
    assert!(pack.exports_cones());
}
