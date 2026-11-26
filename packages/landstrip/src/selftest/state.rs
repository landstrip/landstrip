// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::context::{PolicyDelivery, ResponderMode, RunResult, RunSpec, SandboxContext};
use super::machine::Require;
use super::probe::{Probe, ProbeOutcome};
use proptest::prelude::*;
use proptest::test_runner::{TestCaseError, TestCaseResult};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static STATE_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeKind {
    Dir {
        mode: u32,
    },
    File {
        inode: u64,
        bytes: Vec<u8>,
        mode: u32,
        has_xattr: bool,
    },
    #[cfg(unix)]
    Symlink {
        target: String,
    },
}

impl NodeKind {
    pub fn symlink_target(&self) -> Option<&str> {
        match self {
            #[cfg(unix)]
            Self::Symlink { target } => Some(target),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedTarget {
    Node { rel: String, kind: NodeKind },
    Missing { rel: String, parent_exists: bool },
    Escaped,
    Loop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SelectorKind {
    Literal,
    Glob,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SelectorBase {
    Root,
    Home,
    Relative,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Selector {
    pub kind: SelectorKind,
    pub base: SelectorBase,
    pub rel: String,
}

impl Selector {
    pub fn literal(rel: impl Into<String>) -> Self {
        Self {
            kind: SelectorKind::Literal,
            base: SelectorBase::Root,
            rel: rel.into(),
        }
    }

    pub fn glob(rel: impl Into<String>) -> Self {
        Self {
            kind: SelectorKind::Glob,
            base: SelectorBase::Root,
            rel: rel.into(),
        }
    }

    pub fn with_base(self, base: SelectorBase) -> Self {
        Self { base, ..self }
    }

    pub fn is_glob(&self) -> bool {
        self.kind == SelectorKind::Glob
    }

    pub fn has_glob_bytes(part: &str) -> bool {
        part.bytes().any(|b| matches!(b, b'*' | b'?' | b'[' | b']'))
    }

    pub fn render_value(&self, root: &Path) -> Value {
        let path = match self.base {
            SelectorBase::Root => root.join(&self.rel).to_string_lossy().into_owned(),
            SelectorBase::Home => format!("~/{}", self.rel),
            SelectorBase::Relative => self.rel.clone(),
        };
        if self.kind == SelectorKind::Literal && Self::has_glob_bytes(&path) {
            json!({ "literal": path })
        } else {
            json!(path)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkMode {
    #[default]
    DenyAll,
    #[cfg(unix)]
    LocalBindingOnly,
    #[cfg(unix)]
    ProxyPort(u16),
    AllowAll,
}

/// What `allowRead` starts from before the selectors are added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReadBase {
    /// `/` when `allowRead` is otherwise empty.
    #[default]
    Implicit,
    /// `/` alongside the other selectors.
    Root,
    /// `denyRead: ["/"]`, with only system directories readable.
    Restricted,
}

impl ReadBase {
    pub fn allows_root(self, allow_read: &BTreeSet<Selector>) -> bool {
        match self {
            Self::Implicit => allow_read.is_empty(),
            Self::Root => true,
            Self::Restricted => false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PolicyModel {
    pub read_base: ReadBase,
    pub allow_read: BTreeSet<Selector>,
    pub deny_read: BTreeSet<Selector>,
    pub deny_read_always: BTreeSet<Selector>,
    pub allow_write: BTreeSet<Selector>,
    pub deny_write: BTreeSet<Selector>,
    pub deny_write_always: BTreeSet<Selector>,
    pub network: NetworkMode,
    pub allow_all_unix: bool,
    pub allow_unix: BTreeSet<String>,
    pub delivery: PolicyDelivery,
    pub responder: ResponderMode,
}

impl PolicyModel {
    pub fn standard_seeded() -> Self {
        let mut policy = Self {
            network: NetworkMode::AllowAll,
            delivery: PolicyDelivery::JsonSingle,
            responder: ResponderMode::ObserveFd,
            ..Self::default()
        };
        policy.allow_write.insert(Selector::literal("writable"));
        policy.allow_write.insert(Selector::literal("guarded"));
        policy
            .deny_write
            .insert(Selector::literal("guarded/blocked"));
        policy
            .deny_read
            .insert(Selector::literal("vault/secret.txt"));
        policy
            .deny_read_always
            .insert(Selector::literal("vault/hard.key"));
        policy
            .deny_write_always
            .insert(Selector::literal("writable/immutable.lock"));
        policy
    }

    pub fn to_policy_values(&self, root: &Path) -> Vec<Value> {
        let mut allow_read: Vec<Value> = self
            .allow_read
            .iter()
            .map(|s| s.render_value(root))
            .collect();
        let mut deny_read: Vec<Value> = self
            .deny_read
            .iter()
            .map(|s| s.render_value(root))
            .collect();
        if self.read_base == ReadBase::Restricted {
            deny_read.insert(0, json!("/"));
            for sys in ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/dev"] {
                if Path::new(sys).exists() {
                    allow_read.push(json!(sys));
                }
            }
            if let Ok(exe) = std::env::current_exe()
                && let Some(parent) = exe.parent()
            {
                allow_read.push(json!(parent.to_string_lossy().into_owned()));
            }
        } else if self.read_base.allows_root(&self.allow_read) {
            allow_read.push(json!("/"));
        }

        let mut allow_write: Vec<Value> = self
            .allow_write
            .iter()
            .map(|s| s.render_value(root))
            .collect();
        if cfg!(unix) {
            allow_write.push(json!("/dev/null"));
        }
        let deny_write: Vec<Value> = self
            .deny_write
            .iter()
            .map(|s| s.render_value(root))
            .collect();
        let deny_read_always: Vec<Value> = self
            .deny_read_always
            .iter()
            .map(|s| s.render_value(root))
            .collect();
        let deny_write_always: Vec<Value> = self
            .deny_write_always
            .iter()
            .map(|s| s.render_value(root))
            .collect();

        let net = match self.network {
            NetworkMode::DenyAll => json!({}),
            #[cfg(unix)]
            NetworkMode::LocalBindingOnly => json!({ "allowLocalBinding": true }),
            #[cfg(unix)]
            NetworkMode::ProxyPort(port) => json!({ "httpProxyPort": port }),
            NetworkMode::AllowAll => json!({ "allowNetwork": true }),
        };
        let mut net_obj = net.as_object().cloned().unwrap_or_default();
        if self.allow_all_unix {
            net_obj.insert("allowAllUnixSockets".to_owned(), json!(true));
        } else if !self.allow_unix.is_empty() {
            let paths: Vec<String> = self
                .allow_unix
                .iter()
                .map(|rel| root.join(rel).to_string_lossy().into_owned())
                .collect();
            net_obj.insert("allowUnixSockets".to_owned(), json!(paths));
        }

        if self.delivery == PolicyDelivery::MergedJson {
            let layer_a = json!({
                "filesystem": {
                    "allowRead": allow_read,
                    "denyRead": deny_read,
                    "denyReadAlways": deny_read_always,
                },
                "network": Value::Object(net_obj),
            });
            let layer_b = json!({
                "filesystem": {
                    "allowWrite": allow_write,
                    "denyWrite": deny_write,
                    "denyWriteAlways": deny_write_always,
                }
            });
            vec![layer_a, layer_b]
        } else {
            vec![json!({
                "filesystem": {
                    "allowRead": allow_read,
                    "denyRead": deny_read,
                    "denyReadAlways": deny_read_always,
                    "allowWrite": allow_write,
                    "denyWrite": deny_write,
                    "denyWriteAlways": deny_write_always,
                },
                "network": Value::Object(net_obj),
            })]
        }
    }
}

#[derive(Debug)]
pub struct SandboxState {
    pub ctx: SandboxContext,
    pub root: PathBuf,
    pub nodes: BTreeMap<String, NodeKind>,
    pub policy: PolicyModel,
    pub next_inode: u64,
}

impl Default for SandboxState {
    fn default() -> Self {
        Self::new(SandboxContext::default())
    }
}

impl Drop for SandboxState {
    fn drop(&mut self) {
        let _ = robust_remove(&self.root);
    }
}

impl SandboxState {
    pub fn new(ctx: SandboxContext) -> Self {
        let id = STATE_SEQ.fetch_add(1, Ordering::Relaxed);
        let raw_root = ctx.scratch_root.join(format!("s{id}"));
        let _ = robust_remove(&raw_root);
        let _ = std::fs::create_dir_all(&raw_root);
        let root = std::fs::canonicalize(&raw_root).unwrap_or(raw_root);
        let mut state = Self {
            ctx,
            root,
            nodes: BTreeMap::new(),
            policy: PolicyModel::standard_seeded(),
            next_inode: 100,
        };
        state.seed_initial_tree();
        state
    }
    pub fn alloc_inode(&mut self) -> u64 {
        let ino = self.next_inode;
        self.next_inode += 1;
        ino
    }

    pub fn probe(
        &self,
        policies: &[Value],
        probe: impl Into<Probe>,
    ) -> Result<ProbeOutcome, TestCaseError> {
        let spec = RunSpec::worker(&self.root, policies, &probe.into(), &self.ctx)?;
        ProbeOutcome::try_from(&self.ctx.execute(&spec))
    }

    /// Runs `probe` under `policy`; `~/` selectors resolve to the tree root.
    pub fn run_policy(
        &self,
        policy: &PolicyModel,
        probe: impl Into<Probe>,
    ) -> Result<RunResult, TestCaseError> {
        let policies = policy.to_policy_values(&self.root);
        let home = self.root.to_string_lossy();
        let env = [("HOME", home.as_ref())];
        let mut spec = RunSpec::worker(&self.root, &policies, &probe.into(), &self.ctx)?;
        spec.delivery = policy.delivery;
        spec.responder = policy.responder;
        spec.env_overrides = &env;
        Ok(self.ctx.execute(&spec))
    }

    pub fn abs_path(&self, rel: &str) -> PathBuf {
        if rel.is_empty() || rel == "." {
            self.root.clone()
        } else {
            self.root.join(rel)
        }
    }

    pub fn resolve(&self, rel: &str, follow_last: bool) -> ResolvedTarget {
        self.resolve_traced(rel, follow_last).0
    }

    pub fn resolve_traced(&self, rel: &str, follow_last: bool) -> (ResolvedTarget, Vec<String>) {
        let root = self.root.to_string_lossy();
        let mut pending: Vec<String> = rel
            .split('/')
            .filter(|part| !part.is_empty())
            .rev()
            .map(str::to_owned)
            .collect();
        let mut stack: Vec<String> = Vec::new();
        let mut symlinks: Vec<String> = Vec::new();
        let mut hops = 0usize;
        while let Some(part) = pending.pop() {
            match part.as_str() {
                "." => continue,
                ".." => {
                    if stack.pop().is_none() {
                        return (ResolvedTarget::Escaped, symlinks);
                    }
                    continue;
                }
                _ => stack.push(part),
            }
            let current = stack.join("/");
            let target = self.nodes.get(&current).and_then(NodeKind::symlink_target);
            let Some(target) = target.filter(|_| follow_last || !pending.is_empty()) else {
                continue;
            };
            symlinks.push(current);
            hops += 1;
            if hops > 40 {
                return (ResolvedTarget::Loop, symlinks);
            }
            stack.pop();
            let target = if let Some(inside) = target.strip_prefix(root.as_ref()) {
                stack.clear();
                inside
            } else if target.starts_with('/') {
                return (ResolvedTarget::Escaped, symlinks);
            } else {
                target
            };
            pending.extend(
                target
                    .split('/')
                    .filter(|part| !part.is_empty())
                    .rev()
                    .map(str::to_owned),
            );
        }
        let rel = stack.join("/");
        if let Some(kind) = self.nodes.get(&rel) {
            return (
                ResolvedTarget::Node {
                    rel,
                    kind: kind.clone(),
                },
                symlinks,
            );
        }
        let parent_exists = rel
            .rsplit_once('/')
            .is_none_or(|(parent, _)| matches!(self.nodes.get(parent), Some(NodeKind::Dir { .. })));
        (ResolvedTarget::Missing { rel, parent_exists }, symlinks)
    }

    /// Mirrors `canonicalize_existing_prefix`: the longest prefix that fully
    /// resolves is canonicalized, and the rest is kept as spelled. A dangling
    /// or looping symlink thus keeps its own name.
    pub fn canonical(&self, rel: &str) -> Option<String> {
        let mut parts: Vec<&str> = rel.split('/').filter(|part| !part.is_empty()).collect();
        let mut missing: Vec<&str> = Vec::new();
        let base = loop {
            if parts.is_empty() {
                break String::new();
            }
            match self.resolve(&parts.join("/"), true) {
                ResolvedTarget::Node { rel, .. } => break rel,
                ResolvedTarget::Escaped => return None,
                ResolvedTarget::Missing { .. } | ResolvedTarget::Loop => {
                    missing.extend(parts.pop());
                }
            }
        };
        Some(
            std::iter::once(base.as_str())
                .chain(missing.into_iter().rev())
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join("/"),
        )
    }

    /// Every node, plus the children of each directory symlink spelled
    /// through that link.
    pub fn lexical_paths(&self) -> Vec<String> {
        let mut paths: Vec<String> = self.nodes.keys().cloned().collect();
        for (link, node) in &self.nodes {
            if node.symlink_target().is_none() {
                continue;
            }
            if let ResolvedTarget::Node {
                rel: dir,
                kind: NodeKind::Dir { .. },
            } = self.resolve(link, true)
            {
                let prefix = format!("{dir}/");
                paths.extend(
                    self.nodes
                        .keys()
                        .filter_map(|rel| rel.strip_prefix(&prefix))
                        .filter(|child| !child.contains('/'))
                        .map(|child| format!("{link}/{child}")),
                );
            }
        }
        paths
    }

    fn seed_initial_tree(&mut self) {
        for dir in [
            "open",
            "writable",
            "writable/sub",
            "guarded",
            "guarded/blocked",
            "vault",
            "links",
        ] {
            self.host_mkdir(dir);
        }
        self.host_write_file("open/readme.txt", b"public-readme\n", false);
        self.host_write_file("writable/note.txt", b"initial-note\n", true);
        self.host_write_file("writable/immutable.lock", b"pinned-lock\n", false);
        self.host_write_file("guarded/allowed.txt", b"guarded-ok\n", false);
        self.host_write_file("guarded/blocked/denied.txt", b"blocked-write\n", false);
        self.host_write_file("vault/secret.txt", b"soft-secret\n", true);
        self.host_write_file("vault/hard.key", b"hard-secret-key\n", false);
        #[cfg(unix)]
        {
            self.host_symlink("../open/readme.txt", "links/to_open");
            self.host_symlink("../vault/secret.txt", "links/to_secret");
            self.host_symlink("../writable/note.txt", "links/to_writable");
            self.host_symlink("missing_leaf", "links/dangling");
        }
    }

    pub fn host_mkdir(&mut self, rel: &str) {
        let abs = self.abs_path(rel);
        let _ = std::fs::create_dir_all(&abs);
        let mut prefix = String::new();
        for part in rel.split('/').filter(|p| !p.is_empty()) {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            self.nodes
                .entry(prefix.clone())
                .or_insert(NodeKind::Dir { mode: 0o755 });
        }
    }

    pub fn host_write_file(&mut self, rel: &str, bytes: &[u8], with_xattr: bool) {
        if let Some((parent, _)) = rel.rsplit_once('/') {
            self.host_mkdir(parent);
        }
        let abs = self.abs_path(rel);
        let _ = std::fs::remove_file(&abs);
        let _ = std::fs::write(&abs, bytes);
        let applied_xattr = with_xattr && set_test_xattr(&abs);
        let ino = self.alloc_inode();
        self.nodes.insert(
            rel.to_owned(),
            NodeKind::File {
                inode: ino,
                bytes: bytes.to_vec(),
                mode: 0o644,
                has_xattr: applied_xattr,
            },
        );
    }

    #[cfg(unix)]
    pub fn host_symlink(&mut self, target: &str, link_rel: &str) {
        if let Some((parent, _)) = link_rel.rsplit_once('/') {
            self.host_mkdir(parent);
        }
        let abs = self.abs_path(link_rel);
        let _ = std::fs::remove_file(&abs);
        if std::os::unix::fs::symlink(target, &abs).is_ok() {
            self.nodes.insert(
                link_rel.to_owned(),
                NodeKind::Symlink {
                    target: target.to_owned(),
                },
            );
        }
    }

    pub fn verify_invariants(&self) -> TestCaseResult {
        for (rel, node) in &self.nodes {
            let abs = self.abs_path(rel);
            let meta = std::fs::symlink_metadata(&abs).require(&format!(
                "model node `{rel}` missing from disk at {}",
                abs.display()
            ))?;
            match node {
                NodeKind::Dir { .. } => {
                    prop_assert!(meta.is_dir(), "expected `{rel}` to be a directory on disk");
                }
                NodeKind::File { bytes, .. } => {
                    prop_assert!(meta.is_file(), "expected `{rel}` to be a regular file");
                    let disk_bytes = std::fs::read(&abs).unwrap_or_default();
                    prop_assert_eq!(
                        &disk_bytes,
                        bytes,
                        "file `{rel}` disk content diverged from model",
                        rel = rel
                    );
                }
                #[cfg(unix)]
                NodeKind::Symlink { target } => {
                    prop_assert!(
                        meta.file_type().is_symlink(),
                        "expected `{rel}` to be a symlink"
                    );
                    let disk_target = std::fs::read_link(&abs)
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    prop_assert_eq!(
                        &disk_target,
                        target,
                        "symlink `{rel}` target diverged from model",
                        rel = rel
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub fn set_test_xattr(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(cpath) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    let value = b"landstrip-model";
    unsafe {
        libc::setxattr(
            cpath.as_ptr(),
            c"user.landstrip-test".as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        ) == 0
    }
}

#[cfg(not(target_os = "linux"))]
pub fn set_test_xattr(_path: &Path) -> bool {
    false
}

pub fn robust_remove(path: &Path) -> std::io::Result<()> {
    if std::fs::remove_dir_all(path).is_ok() {
        return Ok(());
    }
    relax_modes(path);
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

#[cfg(unix)]
fn relax_modes(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let child = entry.path();
            if child.is_dir() && !child.is_symlink() {
                relax_modes(&child);
            }
        }
    }
}

#[cfg(not(unix))]
fn relax_modes(_path: &Path) {}
