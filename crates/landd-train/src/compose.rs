//! Speculative composition: `T_0 = base`, `T_i = merge(T_{i-1}, C_i)`.

use landd_core::git::{GitError, GitRepo, Identity, MergeOutcome};
use landd_core::Oid;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Candidate {
    /// What the submitter called it (a branch name or the sha itself).
    pub lane: String,
    pub tip: Oid,
}

/// One landed step of the chain: a two-parent merge of `candidate` onto the
/// previous step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Link {
    pub candidate: Candidate,
    pub merge: Oid,
    pub tree: Oid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "dropped", rename_all = "snake_case")]
pub enum Dropped {
    Conflict { conflicting_paths: Vec<String> },
    /// The tip is already reachable from the chain; there is nothing to merge.
    AlreadyLanded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Composition {
    pub base: Oid,
    pub links: Vec<Link>,
    pub dropped: Vec<(Candidate, Dropped)>,
}

impl Composition {
    /// The commit to test and push: the last merge, or the base when every
    /// candidate was dropped.
    pub fn tip(&self) -> Oid {
        self.links.last().map(|link| link.merge).unwrap_or(self.base)
    }
}

/// Build the chain. A candidate that conflicts with the chain so far is
/// dropped and the next candidate merges onto the same parent, so one
/// conflict costs its peers nothing. Commit ids are a function of the inputs
/// and `who`, so composing the same list twice yields the same chain.
pub fn compose(repo: &GitRepo, base: &Oid, candidates: &[Candidate], who: &Identity) -> Result<Composition, GitError> {
    let mut composition = Composition { base: *base, links: Vec::new(), dropped: Vec::new() };
    let mut current = *base;
    for candidate in candidates {
        if repo.is_ancestor(&candidate.tip, &current)? {
            composition.dropped.push((candidate.clone(), Dropped::AlreadyLanded));
            continue;
        }
        match repo.merge_tree(&current, &candidate.tip)? {
            MergeOutcome::Conflict { conflicting_paths } => {
                composition.dropped.push((candidate.clone(), Dropped::Conflict { conflicting_paths }));
            }
            MergeOutcome::Clean { tree } => {
                let message = format!("Merge {} ({}) via landd", candidate.lane, &candidate.tip.to_hex()[..12]);
                let merge = repo.commit_tree(&tree, &[current, candidate.tip], &message, who)?;
                composition.links.push(Link { candidate: candidate.clone(), merge, tree });
                current = merge;
            }
        }
    }
    Ok(composition)
}

#[cfg(test)]
mod tests {
    use super::*;
    use landd_core::git::testkit::{who, Sandbox};

    fn candidate(lane: &str, tip: Oid) -> Candidate {
        Candidate { lane: lane.into(), tip }
    }

    #[test]
    fn tooth_a_conflict_is_dropped_without_delaying_its_peers() {
        let dir = tempfile::tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), &[("a.txt", "a\n"), ("b.txt", "b\n"), ("c.txt", "c\n")]);
        let one = sandbox.lane("one", "main", &[("a.txt", "one\n")]);
        let clash = sandbox.lane("clash", "main", &[("a.txt", "clash\n")]);
        let three = sandbox.lane("three", "main", &[("c.txt", "three\n")]);
        let repo = sandbox.repo();
        let base = repo.rev_parse("main").unwrap();
        let status = sandbox.git(&["status", "--porcelain"]);

        let list = [candidate("one", one), candidate("clash", clash), candidate("three", three)];
        let started = std::time::Instant::now();
        let composition = compose(&repo, &base, &list, &who()).unwrap();
        let elapsed = started.elapsed();

        assert_eq!(composition.dropped, vec![(list[1].clone(), Dropped::Conflict { conflicting_paths: vec!["a.txt".into()] })]);
        let landed: Vec<&str> = composition.links.iter().map(|l| l.candidate.lane.as_str()).collect();
        assert_eq!(landed, ["one", "three"]);
        // `three` merged onto `one`'s merge: the conflict left no hole in the chain.
        assert_eq!(repo.parents(&composition.links[0].merge).unwrap(), vec![base, one]);
        assert_eq!(repo.parents(&composition.links[1].merge).unwrap(), vec![composition.links[0].merge, three]);
        assert_eq!(composition.tip(), composition.links[1].merge);
        // No working tree, index or ref was touched.
        assert_eq!(sandbox.git(&["status", "--porcelain"]), status);
        assert_eq!(repo.rev_parse("main").unwrap(), base);
        assert!(elapsed.as_millis() < 2000, "composition took {elapsed:?}");

        assert_eq!(compose(&repo, &base, &list, &who()).unwrap(), composition);
    }

    #[test]
    fn already_landed_tips_and_empty_batches() {
        let dir = tempfile::tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), &[("a.txt", "a\n")]);
        let repo = sandbox.repo();
        let base = repo.rev_parse("main").unwrap();
        let one = sandbox.lane("one", "main", &[("b.txt", "one\n")]);
        let list = [candidate("old", base), candidate("one", one), candidate("one-again", one)];
        let composition = compose(&repo, &base, &list, &who()).unwrap();
        assert_eq!(composition.links.len(), 1);
        assert_eq!(composition.dropped, vec![(list[0].clone(), Dropped::AlreadyLanded), (list[2].clone(), Dropped::AlreadyLanded)]);
        let empty = compose(&repo, &base, &[], &who()).unwrap();
        assert_eq!(empty.tip(), base);
    }
}
