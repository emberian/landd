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

/// A lane name that is safe to resolve and to quote: a ref-like name or an
/// object id, with nothing git would read as a revision expression, an
/// option or a second line.
pub fn valid_lane(lane: &str) -> bool {
    !lane.is_empty()
        && lane.len() <= 255
        && !lane.starts_with(['-', '.', '/'])
        && !lane.contains("..")
        && !lane.contains("@{")
        && lane.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
}

/// Who merges. The date is not here: it is derived from the commits merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Committer {
    pub name: String,
    pub email: String,
}

/// One step of the chain: a two-parent merge of `candidate` onto the
/// previous step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Link {
    /// Position of the candidate in the list that was composed.
    pub index: usize,
    pub candidate: Candidate,
    pub merge: Oid,
    pub tree: Oid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "dropped", rename_all = "snake_case")]
pub enum Dropped {
    Conflict {
        conflicting_paths: Vec<String>,
    },
    /// The tip is reachable from the base: the lane has nothing to land.
    OnBase,
    /// The tip is reachable from an earlier candidate of this batch (or is
    /// the same commit). Whether it lands is that candidate's fate.
    Subsumed {
        by: usize,
    },
    /// It merges cleanly and changes nothing: its content is already there.
    NoChange,
    /// It cannot be merged at all: missing commit, unrelated history.
    Unmergeable {
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Composition {
    pub base: Oid,
    pub links: Vec<Link>,
    /// `(position in the composed list, why)`.
    pub dropped: Vec<(usize, Dropped)>,
}

impl Composition {
    /// The commit to test and push: the last merge, or the base when every
    /// candidate was dropped.
    pub fn tip(&self) -> Oid {
        self.links.last().map(|link| link.merge).unwrap_or(self.base)
    }
}

/// Build the chain. A candidate that cannot join it is dropped, with the
/// reason, and the next candidate merges onto the same parent, so one bad
/// candidate costs its peers nothing; only a failure of the repository
/// itself is an error.
///
/// Merge commits are a function of their parents alone: the committer is
/// fixed and the date is the later of the two parents' dates. Composing the
/// same list on the same base therefore yields the same commit ids today
/// and after a restart, which is what lets a delivery be recognised again.
pub fn compose(repo: &GitRepo, base: &Oid, candidates: &[Candidate], who: &Committer) -> Result<Composition, GitError> {
    let mut composition = Composition { base: *base, links: Vec::new(), dropped: Vec::new() };
    let mut current = *base;
    let mut current_tree = repo.tree_of(&base.to_hex())?;
    let mut current_time = repo.commit_time(base)?;
    for (index, candidate) in candidates.iter().enumerate() {
        let mut drop = |why: Dropped| composition.dropped.push((index, why));
        if !repo.has_object(&candidate.tip)? {
            drop(Dropped::Unmergeable { detail: "the commit is not in this repository".into() });
            continue;
        }
        if repo.is_ancestor(&candidate.tip, base)? {
            drop(Dropped::OnBase);
            continue;
        }
        if repo.is_ancestor(&candidate.tip, &current)? {
            // Contained in an earlier link: the first one whose tip holds it.
            let mut carrier = None;
            for link in &composition.links {
                if repo.is_ancestor(&candidate.tip, &link.candidate.tip)? {
                    carrier = Some(link.index);
                    break;
                }
            }
            drop(Dropped::Subsumed { by: carrier.unwrap_or(index) });
            continue;
        }
        if repo.merge_base(&current, &candidate.tip)?.is_none() {
            drop(Dropped::Unmergeable { detail: "no common history with the target".into() });
            continue;
        }
        let tree = match repo.merge_tree(&current, &candidate.tip) {
            Ok(MergeOutcome::Clean { tree }) => tree,
            Ok(MergeOutcome::Conflict { conflicting_paths }) => {
                drop(Dropped::Conflict { conflicting_paths });
                continue;
            }
            Err(GitError::Io(err)) => return Err(GitError::Io(err)),
            Err(other) => {
                drop(Dropped::Unmergeable { detail: other.to_string() });
                continue;
            }
        };
        if tree == current_tree {
            drop(Dropped::NoChange);
            continue;
        }
        let time = current_time.max(repo.commit_time(&candidate.tip)?);
        let lane: String = candidate.lane.chars().map(|c| if c.is_control() { '?' } else { c }).take(200).collect();
        let message = format!("Merge {lane} ({}) via landd", &candidate.tip.to_hex()[..12]);
        let identity = Identity { name: who.name.clone(), email: who.email.clone(), time };
        let merge = repo.commit_tree(&tree, &[current, candidate.tip], &message, &identity)?;
        composition.links.push(Link { index, candidate: candidate.clone(), merge, tree });
        (current, current_tree, current_time) = (merge, tree, time);
    }
    Ok(composition)
}

#[cfg(test)]
mod tests {
    use super::*;
    use landd_core::git::testkit::Sandbox;

    fn candidate(lane: &str, tip: Oid) -> Candidate {
        Candidate { lane: lane.into(), tip }
    }

    fn who() -> Committer {
        Committer { name: "landd".into(), email: "landd@localhost".into() }
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
        let composition = compose(&repo, &base, &list, &who()).unwrap();

        assert_eq!(composition.dropped, vec![(1, Dropped::Conflict { conflicting_paths: vec!["a.txt".into()] })]);
        let landed: Vec<&str> = composition.links.iter().map(|l| l.candidate.lane.as_str()).collect();
        assert_eq!(landed, ["one", "three"]);
        // `three` merged onto `one`'s merge: the conflict left no hole in the chain.
        assert_eq!(repo.parents(&composition.links[0].merge).unwrap(), vec![base, one]);
        assert_eq!(repo.parents(&composition.links[1].merge).unwrap(), vec![composition.links[0].merge, three]);
        assert_eq!(composition.tip(), composition.links[1].merge);
        // No working tree, index or ref was touched.
        assert_eq!(sandbox.git(&["status", "--porcelain"]), status);
        assert_eq!(repo.rev_parse("main").unwrap(), base);
    }

    /// The identity of a merge does not depend on when it is composed.
    #[test]
    fn tooth_merge_commits_are_a_function_of_their_parents() {
        let dir = tempfile::tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), &[("a.txt", "a\n")]);
        let one = sandbox.lane("one", "main", &[("b.txt", "one\n")]);
        let repo = sandbox.repo();
        let base = repo.rev_parse("main").unwrap();
        let first = compose(&repo, &base, &[candidate("one", one)], &who()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        // A second process, a second later.
        let again = compose(&sandbox.repo(), &base, &[candidate("one", one)], &who()).unwrap();
        assert_eq!(first, again);
        assert_eq!(
            repo.commit_time(&first.links[0].merge).unwrap(),
            repo.commit_time(&one).unwrap().max(repo.commit_time(&base).unwrap())
        );
        // Another committer, another commit.
        let other = Committer { name: "someone".into(), ..who() };
        assert_ne!(compose(&repo, &base, &[candidate("one", one)], &other).unwrap().links[0].merge, first.links[0].merge);
    }

    /// A lane that is a prefix of an earlier lane is not "landed" because the
    /// chain contains it: it lands only if that lane does.
    #[test]
    fn tooth_stacked_and_duplicate_lanes_are_subsumed_not_on_base() {
        let dir = tempfile::tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), &[("a.txt", "a\n")]);
        let repo = sandbox.repo();
        let base = repo.rev_parse("main").unwrap();
        let lower = sandbox.lane("lower", "main", &[("b.txt", "lower\n")]);
        let upper = sandbox.lane("upper", "lower", &[("c.txt", "upper\n")]);
        let list =
            [candidate("old", base), candidate("upper", upper), candidate("lower", lower), candidate("upper-again", upper)];
        let composition = compose(&repo, &base, &list, &who()).unwrap();
        assert_eq!(composition.links.len(), 1);
        assert_eq!(
            composition.dropped,
            vec![(0, Dropped::OnBase), (2, Dropped::Subsumed { by: 1 }), (3, Dropped::Subsumed { by: 1 })]
        );
        assert_eq!(compose(&repo, &base, &[], &who()).unwrap().tip(), base);
    }

    #[test]
    fn tooth_one_unmergeable_candidate_does_not_fail_the_batch() {
        let dir = tempfile::tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), &[("a.txt", "a\n")]);
        let good = sandbox.lane("good", "main", &[("b.txt", "good\n")]);
        // A commit with no history in common with main.
        sandbox.git(&["checkout", "--quiet", "--orphan", "island"]);
        let orphan = sandbox.commit("island", "island", &[("z.txt", "z\n")], &[]);
        sandbox.git(&["checkout", "--quiet", "main"]);
        // The same change as `good`, made independently: nothing left to merge.
        let same = sandbox.lane("same", "main", &[("b.txt", "good\n")]);
        let repo = sandbox.repo();
        let base = repo.rev_parse("main").unwrap();
        let absent = Oid::from_slice(&[0xab; 20]).unwrap();
        let list = [candidate("absent", absent), candidate("orphan", orphan), candidate("good", good), candidate("same", same)];
        let composition = compose(&repo, &base, &list, &who()).unwrap();
        assert_eq!(composition.links.len(), 1);
        assert_eq!(composition.links[0].index, 2);
        assert!(matches!(&composition.dropped[0], (0, Dropped::Unmergeable { .. })));
        assert!(matches!(&composition.dropped[1], (1, Dropped::Unmergeable { detail }) if detail.contains("no common history")));
        assert_eq!(composition.dropped[2], (3, Dropped::NoChange));
    }

    #[test]
    fn tooth_lane_names_cannot_carry_revision_syntax_or_trailers() {
        for good in ["lane/pr7-final", "main", "a.b_c-d", "0123456789abcdef0123456789abcdef01234567"] {
            assert!(valid_lane(good), "{good}");
        }
        for bad in [
            "",
            "-x",
            "--upload-pack=x",
            ":/fix",
            "a..b",
            "a^{tree}",
            "a~1",
            "a@{1}",
            "x\nFleet-Seat: y",
            "a b",
            "a:b",
            "../x",
            ".hidden",
            "/abs",
        ] {
            assert!(!valid_lane(bad), "{bad:?}");
        }
    }
}
