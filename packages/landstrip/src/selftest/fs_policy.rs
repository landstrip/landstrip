// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

#[cfg(target_os = "linux")]
use super::context::RunSpec;
use super::context::{PolicyDelivery, ResponderMode};
#[cfg(unix)]
use super::machine::Require;
use super::machine::Step;
use super::oracle::{Decision, Entry, FsOracle, Mutation, RelPath};
#[cfg(unix)]
use super::probe::ChmodVia;
#[cfg(target_os = "linux")]
use super::probe::Probe;
#[cfg(target_os = "linux")]
use super::probe::XattrOp;
use super::probe::{FsProbe, ProbeOutcome, ProbeReply};
use super::state::{
    NodeKind, PolicyModel, ReadBase, ResolvedTarget, SandboxState, Selector, SelectorBase,
};
use proptest::prelude::*;
use proptest::sample::{Index, select};
use proptest::strategy::Union;
use proptest::test_runner::{TestCaseError, TestCaseResult};
use serde_json::json;
#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct HostSeedFile {
    pub slot: usize,
    pub tag: u16,
    pub with_xattr: bool,
}

impl Arbitrary for HostSeedFile {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        (0..7usize, 1..1000u16, any::<bool>())
            .prop_map(|(slot, tag, with_xattr)| Self {
                slot,
                tag,
                with_xattr,
            })
            .boxed()
    }
}

impl Step for HostSeedFile {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        const TARGETS: &[&str] = &[
            "open/seeded.txt",
            "writable/seeded.txt",
            "writable/sub/cert.pem",
            "writable/sub/plain.log",
            "guarded/blocked/extra.txt",
            "vault/extra_secret.txt",
            "writable/[bracket].txt",
        ];
        let rel = TARGETS[self.slot % TARGETS.len()];
        let body = format!("seed-{}\n", self.tag);
        state.host_write_file(rel, body.as_bytes(), self.with_xattr);
        Ok(())
    }
}

#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct HostMakeSymlink {
    pub link_idx: usize,
    pub target_idx: usize,
}

#[cfg(unix)]
impl Arbitrary for HostMakeSymlink {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        (0..4usize, 0..8usize)
            .prop_map(|(link_idx, target_idx)| Self {
                link_idx,
                target_idx,
            })
            .boxed()
    }
}

#[cfg(unix)]
impl Step for HostMakeSymlink {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        const LINKS: &[&str] = &[
            "links/dyn_a",
            "links/dyn_b",
            "writable/sym_out",
            "writable/sym_ok",
        ];
        const TARGETS: &[&str] = &[
            "../open/readme.txt",
            "../vault/secret.txt",
            "../vault/hard.key",
            "../writable/note.txt",
            "nonexistent_target",
            "../vault",
            "../writable",
            "../guarded/blocked",
        ];
        let link_rel = LINKS[self.link_idx % LINKS.len()];
        let target = TARGETS[self.target_idx % TARGETS.len()];
        state.host_symlink(target, link_rel);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyList {
    AllowRead,
    DenyRead,
    DenyReadAlways,
    AllowWrite,
    DenyWrite,
    DenyWriteAlways,
}

/// How a selector is spelled from a path picked in the current tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectorShape {
    Literal,
    Home,
    Star,
    Question,
    Class,
    Recursive,
    Anywhere,
}

/// With `nested`, the path lies inside the latest selector of the opposite
/// polarity, so that rules carve each other the way real policies do.
#[derive(Debug, Clone)]
pub struct SelectorSpec {
    pub list: PolicyList,
    pub shape: SelectorShape,
    pub nested: bool,
    pub path: Index,
}

impl Arbitrary for SelectorSpec {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        let lists = select(vec![
            PolicyList::AllowRead,
            PolicyList::DenyRead,
            PolicyList::DenyReadAlways,
            PolicyList::AllowWrite,
            PolicyList::DenyWrite,
            PolicyList::DenyWriteAlways,
        ]);
        let shapes = select(vec![
            SelectorShape::Literal,
            SelectorShape::Home,
            SelectorShape::Star,
            SelectorShape::Question,
            SelectorShape::Class,
            SelectorShape::Recursive,
            SelectorShape::Anywhere,
        ]);
        (lists, shapes, any::<bool>(), any::<Index>())
            .prop_map(|(list, shape, nested, path)| Self {
                list,
                shape,
                nested,
                path,
            })
            .boxed()
    }
}

impl SelectorSpec {
    fn join(parent: &str, name: &str) -> String {
        if parent.is_empty() {
            name.to_owned()
        } else {
            format!("{parent}/{name}")
        }
    }

    fn selector(&self, list: PolicyList, rel: &str) -> Selector {
        let (parent, name) = rel.rsplit_once('/').unwrap_or(("", rel));
        let extension = name.rsplit_once('.').map(|(_, ext)| format!("*.{ext}"));
        let leaf = extension.clone().unwrap_or_else(|| name.to_owned());
        let mut chars = name.chars();
        let first = chars.next().unwrap_or('x');
        let rest = chars.as_str();
        match self.shape {
            SelectorShape::Literal => Selector::literal(rel),
            SelectorShape::Home => Selector::literal(rel).with_base(SelectorBase::Home),
            SelectorShape::Star => {
                Selector::glob(Self::join(parent, extension.as_deref().unwrap_or("*")))
            }
            SelectorShape::Question => Selector::glob(Self::join(parent, &format!("?{rest}"))),
            SelectorShape::Class => Selector::glob(Self::join(parent, &format!("[{first}]{rest}"))),
            SelectorShape::Recursive => {
                let top = rel.split('/').next().unwrap_or_default();
                Selector::glob(format!("{top}/**/{leaf}"))
            }
            SelectorShape::Anywhere if list == PolicyList::DenyWrite => {
                Selector::glob(format!("**/{leaf}")).with_base(SelectorBase::Relative)
            }
            SelectorShape::Anywhere => Selector::glob(format!("**/{leaf}")),
        }
    }
}

impl PolicyList {
    fn opposite(self) -> Self {
        match self {
            Self::AllowRead => Self::DenyRead,
            Self::AllowWrite => Self::DenyWrite,
            Self::DenyRead | Self::DenyReadAlways => Self::AllowRead,
            Self::DenyWrite | Self::DenyWriteAlways => Self::AllowWrite,
        }
    }

    fn is_allow(self) -> bool {
        matches!(self, Self::AllowRead | Self::AllowWrite)
    }
}

impl SelectorSpec {
    /// Adds the selector after the ones in `history` and returns its list and
    /// the path it was spelled from.
    fn apply(
        &self,
        policy: &mut PolicyModel,
        paths: &[String],
        history: &[(PolicyList, String)],
    ) -> (PolicyList, String) {
        let inside = |dir: &str| -> Vec<String> {
            paths
                .iter()
                .filter(|rel| rel.is_strictly_under(dir))
                .cloned()
                .collect()
        };
        // Carve inside the latest selector of the opposite polarity, or flip
        // against the latest one when there is none.
        let carve = history
            .iter()
            .rev()
            .find(|(list, _)| list.is_allow() != self.list.is_allow())
            .map(|(_, rel)| (self.list, rel))
            .or_else(|| history.last().map(|(_, rel)| (self.list.opposite(), rel)))
            .filter(|_| self.nested);
        let list = carve.map_or(self.list, |(list, _)| list);
        let nested = match carve {
            Some((_, outer)) => {
                let below = inside(outer);
                if below.is_empty() {
                    inside(outer.rsplit_once('/').map_or("", |(parent, _)| parent))
                } else {
                    below
                }
            }
            None => Vec::new(),
        };
        let rel = self
            .path
            .get(if nested.is_empty() { paths } else { &nested })
            .clone();
        let selector = self.selector(list, &rel);
        match list {
            PolicyList::AllowRead => policy.allow_read.insert(selector),
            PolicyList::DenyRead => policy.deny_read.insert(selector),
            PolicyList::DenyReadAlways => policy.deny_read_always.insert(selector),
            PolicyList::AllowWrite => policy.allow_write.insert(selector),
            PolicyList::DenyWrite => policy.deny_write.insert(selector),
            PolicyList::DenyWriteAlways => policy.deny_write_always.insert(selector),
        };
        (list, rel)
    }
}

/// Builds a policy from selectors spelled against the current tree, on top
/// of the seeded policy or of an empty one.
#[derive(Debug, Clone)]
pub struct HostConfigurePolicy {
    pub seeded: bool,
    pub read_base: ReadBase,
    pub selectors: Vec<SelectorSpec>,
    pub delivery: PolicyDelivery,
    pub responder: ResponderMode,
}

impl Arbitrary for HostConfigurePolicy {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        let delivery = select(vec![
            PolicyDelivery::JsonSingle,
            PolicyDelivery::YamlSingle,
            PolicyDelivery::MergedJson,
            PolicyDelivery::StdinJson,
        ]);
        let responder = select(vec![
            ResponderMode::ObserveFd,
            ResponderMode::ObserveSocket,
            ResponderMode::GrantDeny,
            ResponderMode::GrantAllow,
        ]);
        let read_base = select(vec![
            ReadBase::Implicit,
            ReadBase::Root,
            ReadBase::Restricted,
        ]);
        (
            any::<bool>(),
            read_base,
            prop::collection::vec(any::<SelectorSpec>(), 1..8),
            delivery,
            responder,
        )
            .prop_map(|(seeded, read_base, selectors, delivery, responder)| Self {
                seeded,
                read_base,
                selectors,
                delivery,
                responder,
            })
            .boxed()
    }
}

impl Step for HostConfigurePolicy {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        let mut policy = if self.seeded {
            PolicyModel::standard_seeded()
        } else {
            PolicyModel {
                network: state.policy.network,
                ..PolicyModel::default()
            }
        };
        let mut paths = state.lexical_paths();
        paths.extend(fresh_paths(state));
        let mut history: Vec<(PolicyList, String)> = [
            (PolicyList::AllowRead, &policy.allow_read),
            (PolicyList::AllowWrite, &policy.allow_write),
            (PolicyList::DenyRead, &policy.deny_read),
            (PolicyList::DenyReadAlways, &policy.deny_read_always),
            (PolicyList::DenyWrite, &policy.deny_write),
            (PolicyList::DenyWriteAlways, &policy.deny_write_always),
        ]
        .into_iter()
        .flat_map(|(list, selectors)| {
            selectors
                .iter()
                .map(move |selector| (list, selector.rel.clone()))
        })
        .collect();
        for spec in &self.selectors {
            let applied = spec.apply(&mut policy, &paths, &history);
            history.push(applied);
        }
        policy.read_base = self.read_base;
        policy.delivery = self.delivery;
        policy.responder = self.responder;
        state.policy = policy;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct GuestReadProbe {
    pub path: Index,
}

impl Arbitrary for GuestReadProbe {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        any::<Index>().prop_map(|path| Self { path }).boxed()
    }
}

impl Step for GuestReadProbe {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        let candidates: Vec<String> = state
            .lexical_paths()
            .into_iter()
            .filter(|rel| {
                !matches!(
                    state.resolve(rel, false),
                    ResolvedTarget::Node {
                        kind: NodeKind::Dir { .. },
                        ..
                    }
                )
            })
            .collect();
        let rel = self.path.get(&candidates).as_str();
        let probe = FsProbe::Read {
            path: state.abs_path(rel),
        };
        let result = state.run_policy(&state.policy, probe)?;
        let outcome = ProbeOutcome::try_from(&result)?;
        let responder = state.policy.responder;

        let (resolved, symlinks) = state.resolve_traced(rel, true);
        let ResolvedTarget::Node {
            rel: target_rel,
            kind: NodeKind::File { bytes, .. },
        } = resolved
        else {
            prop_assert_eq!(
                outcome,
                ProbeOutcome::Denied,
                "read({}) on non-file unexpectedly succeeded",
                rel
            );
            return Ok(());
        };
        let oracle = state.oracle()?;
        let symlink_denied =
            cfg!(target_os = "macos") && symlinks.iter().any(|link| !oracle.can_read_symlink(link));
        let decision = if symlink_denied {
            Decision::DenyMatch
        } else {
            oracle.read(&target_rel, rel)
        };
        let should_succeed = decision.effective_allow(responder);
        prop_assert_eq!(
            outcome,
            ProbeOutcome::from(should_succeed),
            "read({} -> {}) decision={:?} responder={:?} policy={:?} stderr={}",
            rel,
            target_rel,
            decision,
            responder,
            state.policy,
            result.stderr
        );
        if should_succeed {
            prop_assert_eq!(
                ProbeReply::try_from(&result)?.into_output(),
                bytes,
                "read({}) content mismatch",
                rel
            );
        }
        if decision == Decision::Always {
            let target = state.abs_path(&target_rel);
            prop_assert!(
                !result.traps.iter().any(|t| {
                    t.get("state") == Some("query")
                        && t.get("path").map(Path::new) == Some(target.as_path())
                }),
                "hard denyReadAlways must never emit query trap"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    Write,
    CreateExcl,
    Truncate,
}

#[derive(Debug, Clone)]
pub struct GuestWriteProbe {
    pub path: Index,
    pub mode: WriteMode,
    pub payload_id: u16,
}

impl Arbitrary for GuestWriteProbe {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        let modes = select(vec![
            WriteMode::Write,
            WriteMode::CreateExcl,
            WriteMode::Truncate,
        ]);
        (any::<Index>(), modes, 1..999u16)
            .prop_map(|(path, mode, payload_id)| Self {
                path,
                mode,
                payload_id,
            })
            .boxed()
    }
}

/// A fresh `.txt` and `.pem` name in every directory, so selectors and
/// writes can name paths that do not exist yet.
fn fresh_paths(state: &SandboxState) -> Vec<String> {
    let (dirs, _) = GuestWriteProbe::split_dirs(state);
    dirs.into_iter()
        .flat_map(|rel| [format!("{rel}/fresh.txt"), format!("{rel}/fresh.pem")])
        .collect()
}

impl GuestWriteProbe {
    /// Splits the tree's paths into directories and everything else.
    fn split_dirs(state: &SandboxState) -> (Vec<String>, Vec<String>) {
        state.lexical_paths().into_iter().partition(|rel| {
            matches!(
                state.resolve(rel, true),
                ResolvedTarget::Node {
                    kind: NodeKind::Dir { .. },
                    ..
                }
            )
        })
    }

    /// Existing non-directories, plus the names from [`fresh_paths`].
    fn candidates(state: &SandboxState) -> Vec<String> {
        let (_, mut candidates) = Self::split_dirs(state);
        candidates.extend(fresh_paths(state));
        candidates
    }

    fn expected(
        &self,
        state: &SandboxState,
        rel: &str,
        resolved: &ResolvedTarget,
        symlinks: &[String],
    ) -> Result<bool, TestCaseError> {
        let ((
            ResolvedTarget::Node {
                rel: target,
                kind: NodeKind::File { .. },
            },
            WriteMode::Write | WriteMode::Truncate,
        )
        | (
            ResolvedTarget::Missing {
                rel: target,
                parent_exists: true,
            },
            WriteMode::Write | WriteMode::CreateExcl,
        )) = (resolved, self.mode)
        else {
            return Ok(false);
        };
        let oracle = state.oracle()?;
        // Seatbelt checks file-read-metadata (`readlink`) on every symlink
        // traversed during open/truncate, even for write-only operations.
        if cfg!(target_os = "macos") && symlinks.iter().any(|link| !oracle.can_read_symlink(link)) {
            return Ok(false);
        }
        // Linux brokers `truncate` like any other path mutation.
        let decision = if cfg!(target_os = "linux") && self.mode == WriteMode::Truncate {
            let entry = Entry {
                label: target.clone(),
                lexical: rel.to_owned(),
            };
            oracle.mutation(state, Mutation::Plain, &[entry])
        } else {
            oracle.write(target, rel)
        };
        Ok(decision.effective_allow(state.policy.responder))
    }
}

impl Step for GuestWriteProbe {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        let candidates = Self::candidates(state);
        let rel = self.path.get(&candidates).as_str();
        let path = state.abs_path(rel);
        let payload = format!("mut-{}\n", self.payload_id);
        let probe = match self.mode {
            WriteMode::Write => FsProbe::Write {
                path,
                data: payload.clone(),
            },
            WriteMode::CreateExcl => FsProbe::CreateExcl {
                path,
                data: payload.clone(),
            },
            WriteMode::Truncate => FsProbe::Truncate { path, len: 4 },
        };
        let (resolved, symlinks) = state.resolve_traced(rel, self.mode != WriteMode::CreateExcl);
        let expected_ok = self.expected(state, rel, &resolved, &symlinks)?;
        let result = state.run_policy(&state.policy, probe)?;
        prop_assert_eq!(
            ProbeOutcome::try_from(&result)?,
            ProbeOutcome::from(expected_ok),
            "write({:?}, {} -> {:?}) responder={:?} policy={:?} stderr={}",
            self.mode,
            rel,
            resolved,
            state.policy.responder,
            state.policy,
            result.stderr
        );
        if !expected_ok {
            if let ResolvedTarget::Missing {
                rel: target,
                parent_exists: true,
            } = &resolved
            {
                prop_assert!(
                    matches!(state.abs_path(target).symlink_metadata(), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
                    "denied write changed missing target {target}"
                );
            }
            return Ok(());
        }
        match resolved {
            ResolvedTarget::Node {
                kind: NodeKind::File {
                    inode, mut bytes, ..
                },
                ..
            } => {
                if self.mode == WriteMode::Truncate {
                    bytes.resize(4, 0);
                } else {
                    bytes = payload.into_bytes();
                }
                // Hard links share the content.
                for node in state.nodes.values_mut() {
                    if let NodeKind::File {
                        inode: other,
                        bytes: content,
                        ..
                    } = node
                        && *other == inode
                    {
                        content.clone_from(&bytes);
                    }
                }
            }
            ResolvedTarget::Missing { rel, .. } => {
                let inode = state.alloc_inode();
                state.nodes.insert(
                    rel,
                    NodeKind::File {
                        inode,
                        bytes: payload.into_bytes(),
                        mode: 0o644,
                        has_xattr: false,
                    },
                );
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct GuestEntryMutateProbe {
    pub case_idx: usize,
}

impl Arbitrary for GuestEntryMutateProbe {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        (0..6usize).prop_map(|case_idx| Self { case_idx }).boxed()
    }
}

impl Step for GuestEntryMutateProbe {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        match self.case_idx % 6 {
            0 => Self::check_mkdir_p_existing_denied(state),
            1 => Self::check_deny_read_blocks_delete(state),
            2 => Self::check_deny_read_blocks_ancestor_rename(state),
            #[cfg(unix)]
            3 => Self::check_hardlink_follow_modes(state),
            4 => Self::check_glob_write_carveout(state),
            _ => Self::check_write_root_under_file(state),
        }
    }
}

impl GuestEntryMutateProbe {
    /// A write root below a regular file does not exist, like a missing one,
    /// and must not keep the sandbox from starting.
    fn check_write_root_under_file(state: &SandboxState) -> TestCaseResult {
        let pol = vec![json!({
            "filesystem": {
                "allowRead": ["/"],
                "allowWrite": [state.abs_path("open/readme.txt/below")]
            },
            "network": { "allowNetwork": true }
        })];
        let read = FsProbe::Read {
            path: state.abs_path("open/readme.txt"),
        };
        prop_assert_eq!(state.probe(&pol, read)?, ProbeOutcome::Allowed);
        Ok(())
    }

    fn check_mkdir_p_existing_denied(state: &SandboxState) -> TestCaseResult {
        let pol = vec![json!({
            "filesystem": { "allowRead": ["/"], "allowWrite": ["/dev/null"] },
            "network": { "allowNetwork": true }
        })];
        let mkdir_dir = FsProbe::Mkdir {
            path: state.abs_path("open"),
            parents: true,
        };
        prop_assert_eq!(
            state.probe(&pol, mkdir_dir)?,
            ProbeOutcome::Allowed,
            "mkdir -p on existing denied dir must succeed"
        );
        let mkdir_file = FsProbe::Mkdir {
            path: state.abs_path("open/readme.txt"),
            parents: true,
        };
        prop_assert_eq!(
            state.probe(&pol, mkdir_file)?,
            ProbeOutcome::Denied,
            "mkdir -p on existing denied file must preserve EEXIST failure"
        );
        Ok(())
    }

    fn check_deny_read_blocks_delete(state: &mut SandboxState) -> TestCaseResult {
        state.host_mkdir("writable/protect_dir");
        state.host_write_file("writable/protect_dir/secret.dat", b"keep", false);
        state.host_write_file("writable/protect_dir/sibling.dat", b"drop", false);
        let pol = vec![json!({
            "filesystem": {
                "allowRead": ["/"],
                "allowWrite": [state.abs_path("writable")],
                "denyReadAlways": [state.abs_path("writable/protect_dir/secret.dat")]
            },
            "network": { "allowNetwork": true }
        })];
        let mut check_pm = state.policy.clone();
        check_pm
            .deny_read_always
            .insert(Selector::literal("writable/protect_dir/secret.dat"));
        prop_assert!(
            FsOracle::new(&check_pm, state)?.read_denied_under(state, "writable/protect_dir")
        );

        let unlink_secret = FsProbe::Unlink {
            path: state.abs_path("writable/protect_dir/secret.dat"),
        };
        prop_assert_eq!(
            state.probe(&pol, unlink_secret)?,
            ProbeOutcome::Denied,
            "denyReadAlways file must not be unlinked"
        );
        let unlink_sibling = FsProbe::Unlink {
            path: state.abs_path("writable/protect_dir/sibling.dat"),
        };
        prop_assert_eq!(
            state.probe(&pol, unlink_sibling)?,
            ProbeOutcome::Allowed,
            "readable sibling in writable dir must unlink cleanly"
        );
        state.nodes.remove("writable/protect_dir/sibling.dat");

        let rmdir_tree = FsProbe::Rmdir {
            path: state.abs_path("writable/protect_dir"),
            recursive: true,
        };
        prop_assert_eq!(
            state.probe(&pol, rmdir_tree)?,
            ProbeOutcome::Denied,
            "directory holding denyReadAlways descendant must not be removed"
        );
        prop_assert!(
            state.abs_path("writable/protect_dir/secret.dat").exists(),
            "denyReadAlways file must survive rm -r"
        );
        // rm -r removes the other entries before it reaches the secret, in
        // directory order.
        let removed: Vec<String> = state
            .nodes
            .keys()
            .filter(|rel| {
                rel.is_strictly_under("writable/protect_dir")
                    && state.abs_path(rel).symlink_metadata().is_err()
            })
            .cloned()
            .collect();
        for rel in removed {
            state.nodes.remove(&rel);
        }
        Ok(())
    }

    fn check_deny_read_blocks_ancestor_rename(state: &mut SandboxState) -> TestCaseResult {
        state.host_mkdir("writable/locked_sub");
        state.host_write_file("writable/locked_sub/private.txt", b"secret", false);
        let pol = vec![json!({
            "filesystem": {
                "allowRead": ["/"],
                "allowWrite": [state.abs_path("writable")],
                "denyRead": [state.abs_path("writable/locked_sub/private.txt")]
            },
            "network": { "allowNetwork": true }
        })];
        let rename = FsProbe::Rename {
            from: state.abs_path("writable/locked_sub"),
            to: state.abs_path("writable/moved_sub"),
        };
        prop_assert_eq!(
            state.probe(&pol, rename)?,
            ProbeOutcome::Denied,
            "renaming ancestor of denyRead file must be denied"
        );
        Ok(())
    }

    #[cfg(unix)]
    fn check_hardlink_follow_modes(state: &mut SandboxState) -> TestCaseResult {
        state.host_write_file("writable/hl_src.txt", b"hl-data", false);
        state.host_symlink("hl_src.txt", "writable/hl_sym");
        let _ = std::fs::remove_file(state.abs_path("writable/hl_followed"));
        let _ = std::fs::remove_file(state.abs_path("writable/hl_unfollowed"));
        let pol = vec![json!({
            "filesystem": {
                "allowRead": ["/"],
                "allowWrite": [state.abs_path("writable")],
                "denyWrite": [state.abs_path("writable/blocked_hl")]
            },
            "network": { "allowNetwork": true }
        })];
        for (dst, follow) in [
            ("writable/hl_followed", true),
            ("writable/hl_unfollowed", false),
        ] {
            let link = FsProbe::Link {
                src: state.abs_path("writable/hl_sym"),
                dst: state.abs_path(dst),
                follow,
            };
            prop_assert_eq!(
                state.probe(&pol, link)?,
                ProbeOutcome::Allowed,
                "hardlink to {dst} with follow={follow} must succeed",
                dst = dst,
                follow = follow
            );
        }
        let meta_f = std::fs::symlink_metadata(state.abs_path("writable/hl_followed"))
            .require("followed link exists")?;
        let meta_u = std::fs::symlink_metadata(state.abs_path("writable/hl_unfollowed"))
            .require("unfollowed link exists")?;
        prop_assert!(meta_f.is_file());
        prop_assert!(meta_u.file_type().is_symlink());
        let _ = std::fs::remove_file(state.abs_path("writable/hl_followed"));
        let _ = std::fs::remove_file(state.abs_path("writable/hl_unfollowed"));
        Ok(())
    }

    fn check_glob_write_carveout(state: &mut SandboxState) -> TestCaseResult {
        state.host_mkdir("cache/nested");
        let pol = vec![json!({
            "filesystem": {
                "allowRead": ["/"],
                "allowWrite": [format!("{}/cache/**/*.pem", state.root.display())],
                "denyWrite": ["**/*.pem"]
            },
            "network": { "allowNetwork": true }
        })];
        let allow_pem = FsProbe::Write {
            path: state.abs_path("cache/nested/cert.pem"),
            data: "cert-body".to_owned(),
        };
        let deny_other = FsProbe::Write {
            path: state.abs_path("cache/nested/other.txt"),
            data: "blocked".to_owned(),
        };
        prop_assert_eq!(state.probe(&pol, allow_pem)?, ProbeOutcome::Allowed);
        prop_assert_eq!(state.probe(&pol, deny_other)?, ProbeOutcome::Denied);
        let ino = state.alloc_inode();
        state.nodes.insert(
            "cache/nested/cert.pem".to_owned(),
            NodeKind::File {
                inode: ino,
                bytes: b"cert-body".to_vec(),
                mode: 0o644,
                has_xattr: false,
            },
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryOp {
    Unlink,
    Rename,
    Link,
    Symlink,
}

/// Where an entry change picks its names, beyond anywhere in the tree.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Any,
    /// A selector's path or one of its ancestors, where the policy draws
    /// its lines.
    Selected,
    /// A writable source that is unreadable, or whose parent is, and a
    /// readable and writable name, so that a link or rename carries the
    /// source across a read boundary.
    ReadBoundary,
}

/// Unlinks, renames, hard links or symlinks a generated name under the
/// current policy.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct GuestEntryChangeProbe {
    pub op: EntryOp,
    pub focus: Focus,
    pub from: Index,
    pub to: Index,
}

#[cfg(target_os = "linux")]
impl Arbitrary for GuestEntryChangeProbe {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        let ops = select(vec![
            EntryOp::Unlink,
            EntryOp::Rename,
            EntryOp::Link,
            EntryOp::Symlink,
        ]);
        let focus = select(vec![Focus::Any, Focus::Selected, Focus::ReadBoundary]);
        (ops, focus, any::<Index>(), any::<Index>())
            .prop_map(|(op, focus, from, to)| Self {
                op,
                focus,
                from,
                to,
            })
            .boxed()
    }
}

#[cfg(target_os = "linux")]
impl Step for GuestEntryChangeProbe {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        let mut paths = state.lexical_paths();
        let mut names = GuestWriteProbe::candidates(state);
        if self.focus == Focus::Selected {
            let selected = Self::selected(state);
            paths.retain(|rel| selected.contains(rel.as_str()));
            names.retain(|rel| {
                selected.contains(rel.as_str())
                    || rel
                        .rsplit_once('/')
                        .is_some_and(|(parent, _)| selected.contains(parent))
            });
        }
        let mut sources = if self.op == EntryOp::Symlink {
            paths
                .iter()
                .filter_map(|rel| Self::entry(state, rel))
                .collect()
        } else {
            Self::unpinned(state, &paths)
        };
        let mut names = Self::unpinned(state, &names);
        if self.focus == Focus::ReadBoundary {
            let oracle = state.oracle()?;
            let denied = |rel: &str| oracle.read(rel, rel) != Decision::Allow;
            let writable =
                |entry: &Entry| oracle.write(&entry.label, &entry.lexical) == Decision::Allow;
            sources.retain(|entry| {
                writable(entry)
                    && (denied(&entry.label)
                        || entry
                            .label
                            .rsplit_once('/')
                            .is_some_and(|(parent, _)| denied(parent)))
            });
            names.retain(|entry| {
                writable(entry) && oracle.read(&entry.label, &entry.lexical) == Decision::Allow
            });
        }
        if sources.is_empty() || names.is_empty() {
            return Ok(());
        }
        let source = self.from.get(&sources);
        let name = self.to.get(&names);
        let (src, dst) = (
            state.abs_path(&source.lexical),
            state.abs_path(&name.lexical),
        );
        let same_file = self.op == EntryOp::Rename && Self::same_file(&src, &dst);
        let (probe, mutation, entries) = match self.op {
            EntryOp::Unlink => (
                FsProbe::Unlink { path: src },
                Mutation::Removal,
                vec![source.clone()],
            ),
            EntryOp::Rename => (
                FsProbe::Rename { from: src, to: dst },
                Mutation::Reparent,
                vec![source.clone(), name.clone()],
            ),
            EntryOp::Link => (
                FsProbe::Link {
                    src,
                    dst,
                    follow: false,
                },
                Mutation::Reparent,
                vec![source.clone(), name.clone()],
            ),
            EntryOp::Symlink => (
                FsProbe::Symlink {
                    target: src,
                    link: dst,
                },
                Mutation::Plain,
                vec![name.clone()],
            ),
        };
        let decision = state.oracle()?.mutation(state, mutation, &entries);
        let kernel = self.kernel_allows(state, source, name);
        let expected = kernel && decision.effective_allow(state.policy.responder);
        let result = state.run_policy(&state.policy, probe)?;
        prop_assert_eq!(
            ProbeOutcome::try_from(&result)?,
            ProbeOutcome::from(expected),
            "{:?}({:?}, {:?}) decision={:?} kernel={} responder={:?} policy={:?} stderr={}",
            self.op,
            source,
            name,
            decision,
            kernel,
            state.policy.responder,
            state.policy,
            result.stderr
        );
        if expected && !same_file {
            self.update(state, source, name);
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl GuestEntryChangeProbe {
    /// Paths the fixed scenarios rely on, never removed or replaced.
    const PINNED: &[&str] = &[
        "open/readme.txt",
        "writable/note.txt",
        "links/to_open",
        "links/to_secret",
        "vault/secret.txt",
        "vault/hard.key",
    ];

    /// The paths of the policy's absolute selectors, up to the first glob,
    /// and their ancestors.
    fn selected(state: &SandboxState) -> BTreeSet<&str> {
        let policy = &state.policy;
        [
            &policy.allow_read,
            &policy.deny_read,
            &policy.deny_read_always,
            &policy.allow_write,
            &policy.deny_write,
            &policy.deny_write_always,
        ]
        .into_iter()
        .flatten()
        .filter(|selector| selector.base != SelectorBase::Relative)
        .flat_map(|selector| {
            let end = selector
                .rel
                .split('/')
                .take_while(|part| !Selector::has_glob_bytes(part))
                .map(|part| part.len() + 1)
                .sum::<usize>();
            selector.rel[..end.saturating_sub(1)].lineage()
        })
        .collect()
    }

    fn entry(state: &SandboxState, rel: &str) -> Option<Entry> {
        match state.resolve(rel, false) {
            ResolvedTarget::Node { rel: label, .. }
            | ResolvedTarget::Missing { rel: label, .. } => Some(Entry {
                label,
                lexical: rel.to_owned(),
            }),
            ResolvedTarget::Escaped | ResolvedTarget::Loop => None,
        }
    }

    fn unpinned(state: &SandboxState, paths: &[String]) -> Vec<Entry> {
        paths
            .iter()
            .filter_map(|rel| Self::entry(state, rel))
            .filter(|entry| {
                !entry.label.is_empty()
                    && !Self::PINNED
                        .iter()
                        .any(|pinned| pinned.is_under(&entry.label))
            })
            .collect()
    }

    /// `rename` between two names of one inode succeeds and changes nothing.
    fn same_file(left: &Path, right: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        match (left.symlink_metadata(), right.symlink_metadata()) {
            (Ok(left), Ok(right)) => (left.dev(), left.ino()) == (right.dev(), right.ino()),
            _ => false,
        }
    }

    fn kernel_allows(&self, state: &SandboxState, source: &Entry, name: &Entry) -> bool {
        let is_dir = |node: &NodeKind| matches!(node, NodeKind::Dir { .. });
        let creatable = matches!(
            state.resolve(&name.lexical, false),
            ResolvedTarget::Missing {
                parent_exists: true,
                ..
            }
        );
        let source_node = state.nodes.get(&source.label);
        let name_node = state.nodes.get(&name.label);
        match self.op {
            EntryOp::Unlink => source_node.is_some_and(|node| !is_dir(node)),
            EntryOp::Link => source_node.is_some_and(|node| !is_dir(node)) && creatable,
            EntryOp::Symlink => creatable,
            EntryOp::Rename => match (source_node, name_node) {
                (None, _) => false,
                (Some(node), None) if is_dir(node) => {
                    creatable && !name.label.is_under(&source.label)
                }
                (Some(_), None) => creatable,
                (Some(node), Some(other)) => !is_dir(node) && !is_dir(other),
            },
        }
    }

    fn update(&self, state: &mut SandboxState, source: &Entry, name: &Entry) {
        match self.op {
            EntryOp::Unlink => {
                state.nodes.remove(&source.label);
            }
            EntryOp::Link => {
                if let Some(node) = state.nodes.get(&source.label).cloned() {
                    state.nodes.insert(name.label.clone(), node);
                }
            }
            EntryOp::Symlink => {
                let target = state.abs_path(&source.lexical);
                state.nodes.insert(
                    name.label.clone(),
                    NodeKind::Symlink {
                        target: target.to_string_lossy().into_owned(),
                    },
                );
            }
            EntryOp::Rename => {
                let moved: Vec<String> = state
                    .nodes
                    .keys()
                    .filter(|rel| rel.is_under(&source.label))
                    .cloned()
                    .collect();
                for rel in moved {
                    if let Some(node) = state.nodes.remove(&rel) {
                        let rest = &rel[source.label.len()..];
                        state.nodes.insert(format!("{}{rest}", name.label), node);
                    }
                }
            }
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct GuestMetadataXattrProbe {
    pub sub_idx: usize,
}

#[cfg(unix)]
impl Arbitrary for GuestMetadataXattrProbe {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        (0..4usize).prop_map(|sub_idx| Self { sub_idx }).boxed()
    }
}

#[cfg(unix)]
impl Step for GuestMetadataXattrProbe {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        let policy = PolicyModel {
            responder: ResponderMode::None,
            ..state.policy.clone()
        };
        let oracle = state.oracle()?;
        let outcome = |probe: FsProbe| ProbeOutcome::try_from(&state.run_policy(&policy, probe)?);
        // Both probes open the file read-only before changing its metadata.
        let expected = |rel: &str| {
            ProbeOutcome::from(
                oracle.read(rel, rel).effective_allow(policy.responder)
                    && oracle.write(rel, rel).effective_allow(policy.responder),
            )
        };
        match self.sub_idx % 4 {
            0 => {
                for rel in ["writable/note.txt", "open/readme.txt"] {
                    let probe = FsProbe::Utimens {
                        path: state.abs_path(rel),
                    };
                    prop_assert_eq!(outcome(probe)?, expected(rel), "utimens({})", rel);
                }
            }
            1 => {
                for (rel, mode) in [("writable/note.txt", 0o644), ("open/readme.txt", 0o600)] {
                    let probe = FsProbe::Chmod {
                        path: state.abs_path(rel),
                        mode,
                        via: ChmodVia::Fd,
                    };
                    prop_assert_eq!(outcome(probe)?, expected(rel), "chmod({})", rel);
                }
            }
            #[cfg(target_os = "linux")]
            2 => Self::check_xattr(state)?,
            #[cfg(target_os = "linux")]
            _ => {
                let nofollow = FsProbe::Chmod {
                    path: state.abs_path("links/to_open"),
                    mode: 0o600,
                    via: ChmodVia::NoFollow,
                };
                prop_assert_eq!(outcome(nofollow)?, ProbeOutcome::Denied);
            }
            #[cfg(not(target_os = "linux"))]
            _ => {}
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl GuestMetadataXattrProbe {
    /// Runs under the seeded policy: xattr access is a syscall-surface
    /// check, not a policy decision.
    fn check_xattr(state: &mut SandboxState) -> TestCaseResult {
        state.host_write_file("writable/xattr_probe.txt", b"xa", true);
        let mut policy = PolicyModel {
            delivery: state.policy.delivery,
            ..PolicyModel::standard_seeded()
        };
        let path = state.abs_path("writable/xattr_probe.txt");
        for op in [XattrOp::List, XattrOp::LList, XattrOp::FList] {
            let probe = FsProbe::Xattr {
                path: path.clone(),
                op,
            };
            let res = state.run_policy(&policy, probe)?;
            prop_assert_eq!(
                ProbeReply::try_from(&res)?,
                ProbeReply::Allowed {
                    output: b"found".into()
                }
            );
        }
        let remove = FsProbe::Xattr {
            path,
            op: XattrOp::FRemove,
        };
        let res = state.run_policy(&policy, remove)?;
        prop_assert_eq!(ProbeOutcome::try_from(&res)?, ProbeOutcome::Allowed);

        let symlink_list = FsProbe::Xattr {
            path: state.abs_path("links/to_secret"),
            op: XattrOp::LList,
        };
        let res = state.run_policy(&policy, symlink_list)?;
        prop_assert_eq!(
            ProbeReply::try_from(&res)?,
            ProbeReply::Allowed {
                output: b"absent".into()
            }
        );

        policy.responder = ResponderMode::GrantDeny;
        let denied_set = FsProbe::Xattr {
            path: state.abs_path("open/readme.txt"),
            op: XattrOp::Set,
        };
        let res = state.run_policy(&policy, denied_set)?;
        prop_assert_eq!(ProbeOutcome::try_from(&res)?, ProbeOutcome::Denied);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct GuestOpenat2IoProbe;

#[cfg(target_os = "linux")]
impl Arbitrary for GuestOpenat2IoProbe {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        Just(Self).boxed()
    }
}

#[cfg(target_os = "linux")]
impl Step for GuestOpenat2IoProbe {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        let pol = vec![json!({
            "filesystem": {
                "allowRead": ["/"],
                "allowWrite": [state.abs_path("writable")]
            },
            "network": { "allowNetwork": true }
        })];
        state.host_mkdir("writable/oa2");
        let dir = state.abs_path("writable/oa2");
        prop_assert_eq!(
            state.probe(&pol, FsProbe::Openat2 { dir: dir.clone() })?,
            ProbeOutcome::Allowed,
            "openat2 RESOLVE_* probe failed"
        );
        prop_assert_eq!(
            state.probe(&pol, FsProbe::IoSurface { dir })?,
            ProbeOutcome::Allowed,
            "preadv2/pwritev2/fsync/memfd probe failed"
        );
        let _ = std::fs::remove_dir_all(state.abs_path("writable/oa2"));
        state.nodes.remove("writable/oa2");
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct InteractiveGrantProbe {
    pub allow_grant: bool,
}

#[cfg(target_os = "linux")]
impl Arbitrary for InteractiveGrantProbe {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        any::<bool>()
            .prop_map(|allow_grant| Self { allow_grant })
            .boxed()
    }
}

#[cfg(target_os = "linux")]
impl Step for InteractiveGrantProbe {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        state.host_write_file("vault/grant_target.txt", b"granted-payload", false);
        let pol = vec![json!({
            "filesystem": {
                "allowRead": ["/"],
                "denyRead": [state.abs_path("vault/grant_target.txt")],
                "denyReadAlways": [state.abs_path("vault/hard.key")],
                "allowWrite": ["/dev/null", state.abs_path("vault/grant_target.txt")]
            },
            "network": { "allowNetwork": true }
        })];
        let read_soft = Probe::from(FsProbe::Read {
            path: state.abs_path("vault/grant_target.txt"),
        });
        let mut soft_spec = RunSpec {
            workdir: &state.root,
            cwd: None,
            policies: &pol,
            delivery: PolicyDelivery::JsonSingle,
            responder: if self.allow_grant {
                ResponderMode::GrantAllow
            } else {
                ResponderMode::GrantDeny
            },
            rename_on_query: None,
            inherited_fds: &[],
            env_overrides: &[],
            tool: &state.ctx.exe,
            args: read_soft.argv()?,
            timeout: Duration::from_secs(15),
        };
        let soft_res = state.ctx.execute(&soft_spec);
        prop_assert!(
            soft_res
                .traps
                .iter()
                .any(|t| t.get("state") == Some("query")),
            "expected interactive query trap on soft denyRead"
        );
        prop_assert_eq!(
            ProbeOutcome::try_from(&soft_res)?,
            ProbeOutcome::from(self.allow_grant)
        );
        if self.allow_grant {
            prop_assert_eq!(
                ProbeReply::try_from(&soft_res)?.into_output(),
                b"granted-payload"
            );
        }

        let grant_target = state.abs_path("vault/grant_target.txt");
        prop_assert_eq!(
            soft_res.traps.iter().any(|t| {
                t.get("state") == Some("info")
                    && t.get("path").map(Path::new) == Some(grant_target.as_path())
            }),
            !self.allow_grant,
            "denied interactive query must emit state=info denial trap"
        );
        Self::verify_memo_and_deferral(state, &mut soft_spec, &grant_target)?;

        soft_spec.args = Probe::from(FsProbe::Unlink { path: grant_target }).argv()?;
        let unlink_res = state.ctx.execute(&soft_spec);
        prop_assert!(
            unlink_res
                .traps
                .iter()
                .any(|t| t.get("state") == Some("query")),
            "expected interactive query trap on removing a soft denyRead name"
        );
        prop_assert_eq!(
            ProbeOutcome::try_from(&unlink_res)?,
            ProbeOutcome::from(self.allow_grant)
        );
        if self.allow_grant {
            state.nodes.remove("vault/grant_target.txt");
        }

        let read_hard = Probe::from(FsProbe::Read {
            path: state.abs_path("vault/hard.key"),
        });
        soft_spec.args = read_hard.argv()?;
        soft_spec.responder = ResponderMode::GrantAllow;
        let hard_res = state.ctx.execute(&soft_spec);
        prop_assert_eq!(
            ProbeOutcome::try_from(&hard_res)?,
            ProbeOutcome::Denied,
            "denyReadAlways must reject even with GrantAllow"
        );
        prop_assert!(
            !hard_res
                .traps
                .iter()
                .any(|t| t.get("state") == Some("query")),
            "denyReadAlways must never emit query"
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl InteractiveGrantProbe {
    fn verify_memo_and_deferral(
        state: &SandboxState,
        soft_spec: &mut RunSpec<'_>,
        grant_target: &Path,
    ) -> TestCaseResult {
        let repeat_read = Probe::from(super::probe::ExitProbe::ReadAttempts {
            path: grant_target.to_path_buf(),
            attempts: 3,
            exit_code: 0,
        });
        soft_spec.args = repeat_read.argv()?;
        let repeat_res = state.ctx.execute(soft_spec);
        let query_count = repeat_res
            .traps
            .iter()
            .filter(|t| {
                t.get("state") == Some("query")
                    && t.get("path").map(Path::new) == Some(grant_target)
            })
            .count();
        prop_assert_eq!(
            query_count,
            1,
            "repeated accesses in one run must query once: {:?}",
            repeat_res.traps
        );

        let unlisted = state.abs_path("vault/unlisted.txt");
        let _ = std::fs::write(&unlisted, b"unlisted");
        let allow_miss_pol = vec![json!({
            "filesystem": {
                "denyRead": ["/"],
                "allowRead": [
                    "/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/dev",
                    &state.ctx.exe
                ],
                "allowWrite": ["/dev/null"]
            },
            "network": { "allowNetwork": true }
        })];
        let mut miss_spec = RunSpec {
            workdir: soft_spec.workdir,
            cwd: soft_spec.cwd,
            policies: &allow_miss_pol,
            delivery: soft_spec.delivery,
            responder: ResponderMode::GrantDeny,
            rename_on_query: None,
            inherited_fds: soft_spec.inherited_fds,
            env_overrides: soft_spec.env_overrides,
            tool: soft_spec.tool,
            args: Probe::from(super::probe::ExitProbe::ReadAttempts {
                path: unlisted.clone(),
                attempts: 2,
                exit_code: 0,
            })
            .argv()?,
            timeout: soft_spec.timeout,
        };
        let miss_ok = state.ctx.execute(&miss_spec);
        prop_assert!(
            !miss_ok.traps.iter().any(|t| {
                t.get("state") == Some("info")
                    && t.get("path").map(Path::new) == Some(unlisted.as_path())
            }),
            "AllowMiss query denied on a successful command must not flush state=info: {:?}",
            miss_ok.traps
        );
        miss_spec.args = Probe::from(super::probe::ExitProbe::ReadAttempts {
            path: unlisted.clone(),
            attempts: 2,
            exit_code: 1,
        })
        .argv()?;
        let miss_fail = state.ctx.execute(&miss_spec);
        prop_assert!(
            miss_fail.traps.iter().any(|t| {
                t.get("state") == Some("info")
                    && t.get("path").map(Path::new) == Some(unlisted.as_path())
            }),
            "AllowMiss query denied on a failing command must flush state=info: {:?}",
            miss_fail.traps
        );
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum FsPolicyStep {
    HostSeedFile(HostSeedFile),
    #[cfg(unix)]
    HostMakeSymlink(HostMakeSymlink),
    HostConfigurePolicy(HostConfigurePolicy),
    GuestReadProbe(GuestReadProbe),
    GuestWriteProbe(GuestWriteProbe),
    GuestEntryMutateProbe(GuestEntryMutateProbe),
    #[cfg(target_os = "linux")]
    GuestEntryChangeProbe(GuestEntryChangeProbe),
    #[cfg(unix)]
    GuestMetadataXattrProbe(GuestMetadataXattrProbe),
    #[cfg(target_os = "linux")]
    GuestOpenat2IoProbe(GuestOpenat2IoProbe),
    #[cfg(target_os = "linux")]
    InteractiveGrantProbe(InteractiveGrantProbe),
}

impl Arbitrary for FsPolicyStep {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        let mut steps = Vec::new();
        steps.extend([
            any::<HostSeedFile>().prop_map(Self::HostSeedFile).boxed(),
            any::<HostConfigurePolicy>()
                .prop_map(Self::HostConfigurePolicy)
                .boxed(),
            any::<GuestReadProbe>()
                .prop_map(Self::GuestReadProbe)
                .boxed(),
            any::<GuestWriteProbe>()
                .prop_map(Self::GuestWriteProbe)
                .boxed(),
            any::<GuestEntryMutateProbe>()
                .prop_map(Self::GuestEntryMutateProbe)
                .boxed(),
        ]);
        #[cfg(unix)]
        steps.push(
            any::<HostMakeSymlink>()
                .prop_map(Self::HostMakeSymlink)
                .boxed(),
        );
        #[cfg(unix)]
        steps.push(
            any::<GuestMetadataXattrProbe>()
                .prop_map(Self::GuestMetadataXattrProbe)
                .boxed(),
        );
        #[cfg(target_os = "linux")]
        steps.push(
            any::<GuestEntryChangeProbe>()
                .prop_map(Self::GuestEntryChangeProbe)
                .boxed(),
        );
        #[cfg(target_os = "linux")]
        steps.push(
            any::<GuestOpenat2IoProbe>()
                .prop_map(Self::GuestOpenat2IoProbe)
                .boxed(),
        );
        #[cfg(target_os = "linux")]
        steps.push(
            any::<InteractiveGrantProbe>()
                .prop_map(Self::InteractiveGrantProbe)
                .boxed(),
        );
        Union::new(steps).boxed()
    }
}

impl AsRef<dyn Step> for FsPolicyStep {
    fn as_ref(&self) -> &(dyn Step + 'static) {
        match self {
            Self::HostSeedFile(step) => step,
            #[cfg(unix)]
            Self::HostMakeSymlink(step) => step,
            Self::HostConfigurePolicy(step) => step,
            Self::GuestReadProbe(step) => step,
            Self::GuestWriteProbe(step) => step,
            Self::GuestEntryMutateProbe(step) => step,
            #[cfg(target_os = "linux")]
            Self::GuestEntryChangeProbe(step) => step,
            #[cfg(unix)]
            Self::GuestMetadataXattrProbe(step) => step,
            #[cfg(target_os = "linux")]
            Self::GuestOpenat2IoProbe(step) => step,
            #[cfg(target_os = "linux")]
            Self::InteractiveGrantProbe(step) => step,
        }
    }
}
