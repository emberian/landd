//! `landd pre-receive`: the forge-side check that a protected ref only moves
//! forward, and only with a verified land receipt for exactly that move.

use landd_core::custody::{self, CustodyEnvelopeV2, TrustedKeys};
use landd_core::digest::hex_decode;
use landd_core::Oid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdate {
    pub old: Oid,
    pub new: Oid,
    pub name: String,
}

/// Parse the hook's stdin: `<old> <new> <ref>` per line.
pub fn parse_updates(stdin: &str) -> Result<Vec<RefUpdate>, String> {
    stdin
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let mut fields = line.split(' ');
            match (fields.next(), fields.next(), fields.next(), fields.next()) {
                (Some(old), Some(new), Some(name), None) => Ok(RefUpdate {
                    old: Oid::from_hex(old).map_err(|e| e.to_string())?,
                    new: Oid::from_hex(new).map_err(|e| e.to_string())?,
                    name: name.to_owned(),
                }),
                _ => Err(format!("malformed ref update line {line:?}")),
            }
        })
        .collect()
}

/// Most push options inspected by `landd pre-receive`.
pub const MAX_PUSH_OPTIONS: usize = 64;
/// Ceiling on `landd pre-receive` stdin bytes (ref update lines).
pub const MAX_HOOK_STDIN_BYTES: u64 = 1 << 20;

/// The receipts carried as `landd-custody=<hex>` push options.
pub fn receipts(push_options: &[String]) -> Vec<CustodyEnvelopeV2> {
    let prefix = format!("{}=", custody::PUSH_OPTION);
    push_options
        .iter()
        .take(MAX_PUSH_OPTIONS)
        .filter(|option| option.len() <= custody::MAX_PUSH_OPTION_BYTES)
        .filter_map(|option| option.strip_prefix(prefix.as_str()))
        .filter_map(hex_decode)
        .filter_map(|wire| CustodyEnvelopeV2::from_wire(&wire).ok())
        .collect()
}

/// Every update of a protected ref needs a receipt that verifies, from a
/// key granted the `land-receipt` kind, whose subject is that exact
/// `(repository, ref, old, new)`. Deleting a protected ref is refused.
/// `is_fast_forward` answers whether `old` is an ancestor of `new`.
pub fn check(
    repo_id: &str,
    updates: &[RefUpdate],
    push_options: &[String],
    trusted: &TrustedKeys,
    protect: &[String],
    is_fast_forward: impl Fn(&Oid, &Oid) -> bool,
) -> Result<(), String> {
    let receipts = receipts(push_options);
    for update in updates.iter().filter(|u| protect.contains(&u.name)) {
        if update.new.is_zero() {
            return Err(format!("{} is protected and cannot be deleted", update.name));
        }
        if !update.old.is_zero() && !is_fast_forward(&update.old, &update.new) {
            return Err(format!("{} would not fast-forward from {} to {}", update.name, update.old, update.new));
        }
        let subject = custody::ref_update_subject(repo_id, &update.name, &update.old, &update.new);
        let verified =
            receipts.iter().any(|r| r.header.kind == "land-receipt" && r.header.subject == subject && r.verify(trusted).is_ok());
        if !verified {
            return Err(format!(
                "{}: no verified land receipt for {} -> {} (push through landd)",
                update.name, update.old, update.new
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use landd_core::custody::{Grant, SigningKey};
    use landd_core::digest::hex_encode;
    use serde_json::json;

    const MAIN: &str = "refs/heads/main";
    const REPO: &str = "ssh://forge/project";

    fn oid(n: u8) -> Oid {
        Oid::from_slice(&[n; 20]).unwrap()
    }

    fn update(old: u8, new: u8, name: &str) -> RefUpdate {
        RefUpdate { old: oid(old), new: oid(new), name: name.into() }
    }

    fn option(key: &SigningKey, kind: &str, name: &str, old: u8, new: u8) -> String {
        let subject = custody::ref_update_subject(REPO, name, &oid(old), &oid(new));
        let receipt = CustodyEnvelopeV2::seal(key, "seat", "seat", kind, subject, json!({"batch_size": 1})).unwrap();
        format!("{}={}", custody::PUSH_OPTION, hex_encode(&receipt.to_wire().unwrap()))
    }

    fn trusted(key: &SigningKey) -> TrustedKeys {
        let mut keys = TrustedKeys::new();
        keys.insert("seat", key.trusted(), Grant::new(&["seat"], &["land-receipt", "runner-attestation"])).unwrap();
        keys
    }

    #[test]
    fn stdin_lines_parse_strictly() {
        let line = format!("{} {} {MAIN}\n", oid(1), oid(2));
        assert_eq!(parse_updates(&line).unwrap(), vec![update(1, 2, MAIN)]);
        assert!(parse_updates("abc def refs/heads/main\n").is_err());
        assert!(parse_updates(&format!("{} {}\n", oid(1), oid(2))).is_err());
        assert!(parse_updates("").unwrap().is_empty());
    }

    #[test]
    fn a_receipt_for_exactly_this_update_is_accepted() {
        let key = SigningKey::ed25519_from_seed([3; 32]);
        let protect = vec![MAIN.to_owned()];
        let options = vec!["unrelated=1".to_owned(), option(&key, "land-receipt", MAIN, 1, 2)];
        check(REPO, &[update(1, 2, MAIN)], &options, &trusted(&key), &protect, |_, _| true).unwrap();
        // Unprotected refs need nothing.
        check(REPO, &[update(1, 2, "refs/heads/lane/x")], &[], &trusted(&key), &protect, |_, _| false).unwrap();
    }

    #[test]
    fn tooth_everything_else_is_refused() {
        let key = SigningKey::ed25519_from_seed([3; 32]);
        let stranger = SigningKey::ed25519_from_seed([4; 32]);
        let protect = vec![MAIN.to_owned()];
        let keys = trusted(&key);
        let refused = |updates: &[RefUpdate], options: &[String], ff: bool| {
            check(REPO, updates, options, &keys, &protect, |_, _| ff).is_err()
        };
        let good = option(&key, "land-receipt", MAIN, 1, 2);

        assert!(refused(&[update(1, 2, MAIN)], &[], true), "no receipt");
        assert!(refused(&[update(1, 3, MAIN)], std::slice::from_ref(&good), true), "receipt for another new tip");
        assert!(refused(&[update(9, 2, MAIN)], std::slice::from_ref(&good), true), "receipt for another old tip");
        assert!(refused(&[update(1, 2, MAIN)], &[option(&key, "land-receipt", "refs/heads/other", 1, 2)], true), "another ref");
        assert!(refused(&[update(1, 2, MAIN)], &[option(&stranger, "land-receipt", MAIN, 1, 2)], true), "untrusted key");
        assert!(refused(&[update(1, 2, MAIN)], &[option(&key, "runner-attestation", MAIN, 1, 2)], true), "wrong kind");
        assert!(refused(&[update(1, 2, MAIN)], std::slice::from_ref(&good), false), "not a fast-forward");
        assert!(refused(&[update(1, 0, MAIN)], &[option(&key, "land-receipt", MAIN, 1, 0)], true), "deletion");
        assert!(refused(&[update(1, 2, MAIN)], &[format!("{}=zz", custody::PUSH_OPTION)], true), "garbage option");
        // One good receipt does not cover a second protected update in the same push.
        let both = vec![MAIN.to_owned(), "refs/heads/release".to_owned()];
        let updates = [update(1, 2, MAIN), update(1, 2, "refs/heads/release")];
        assert!(check(REPO, &updates, std::slice::from_ref(&good), &keys, &both, |_, _| true).is_err());
        // The same receipt presented to a mirror of the repository.
        assert!(check(
            "ssh://forge/project-mirror",
            &[update(1, 2, MAIN)],
            std::slice::from_ref(&good),
            &keys,
            &protect,
            |_, _| true
        )
        .is_err());
        // A key granted only the runner role cannot admit a ref update.
        let mut runner_only = TrustedKeys::new();
        runner_only.insert("seat", key.trusted(), Grant::new(&["seat"], &["runner-attestation"])).unwrap();
        assert!(check(REPO, &[update(1, 2, MAIN)], &[good], &runner_only, &protect, |_, _| true).is_err());

        // Oversized push options are dropped before hex decoding.
        let giant = format!("{}={}", custody::PUSH_OPTION, "aa".repeat(custody::MAX_PUSH_OPTION_BYTES));
        assert!(receipts(&[giant]).is_empty());
    }
}
