//! The example configuration in the repository parses and matches the defaults.

use landd_core::LandConfig;

#[test]
fn example_config_is_the_default_config() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/landd.toml")).unwrap();
    assert_eq!(LandConfig::from_toml(&text).unwrap(), LandConfig::default());
}
