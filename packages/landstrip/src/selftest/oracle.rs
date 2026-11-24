// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Reference model of the filesystem policy. It mirrors `policy/resolver.rs`
//! on Linux: literal selectors are canonicalized, globs keep their lexical
//! and canonical spellings, allow globs grant their existing matches, and an
//! allow overrides a deny only when it is more specific.

use super::context::ResponderMode;
use super::state::{
    NodeKind, PolicyModel, ReadBase, ResolvedTarget, SandboxState, Selector, SelectorBase,
};
use globset::{GlobBuilder, GlobMatcher};
use proptest::test_runner::TestCaseError;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    DenyMatch,
    AllowMiss,
    Always,
}

impl Decision {
    /// Every denial except a hard one is offered to the responder.
    pub fn effective_allow(self, responder: ResponderMode) -> bool {
        let granted = cfg!(target_os = "linux") && responder == ResponderMode::GrantAllow;
        match self {
            Self::Allow => true,
            Self::DenyMatch | Self::AllowMiss => granted,
            Self::Always => false,
        }
    }
}

pub trait RelPath {
    fn is_under(&self, root: &str) -> bool;
    fn is_strictly_under(&self, root: &str) -> bool;
    fn lineage(&self) -> impl Iterator<Item = &str>;
}

impl RelPath for str {
    fn is_under(&self, root: &str) -> bool {
        root.is_empty()
            || self == root
            || self
                .strip_prefix(root)
                .is_some_and(|rest| rest.starts_with('/'))
    }

    fn is_strictly_under(&self, root: &str) -> bool {
        self != root && self.is_under(root)
    }

    fn lineage(&self) -> impl Iterator<Item = &str> {
        std::iter::successors(Some(self).filter(|path| !path.is_empty()), |path| {
            path.rsplit_once('/').map(|(parent, _)| parent)
        })
    }
}

#[derive(Debug, Clone)]
enum Rule {
    Root(String),
    Pattern {
        base: String,
        pattern: String,
        matcher: GlobMatcher,
    },
}

impl Rule {
    fn pattern(pattern: String) -> Result<Self, TestCaseError> {
        let matcher = GlobBuilder::new(&pattern)
            .literal_separator(true)
            .backslash_escape(false)
            .allow_unclosed_class(true)
            .build()
            .map_err(|error| TestCaseError::fail(format!("model glob `{pattern}`: {error}")))?
            .compile_matcher();
        Ok(Self::Pattern {
            base: Self::literal_base(&pattern),
            pattern,
            matcher,
        })
    }

    /// The components of `pattern` before its first glob.
    fn literal_base(pattern: &str) -> String {
        pattern
            .split('/')
            .take_while(|part| !Selector::has_glob_bytes(part))
            .collect::<Vec<_>>()
            .join("/")
    }

    fn base(&self) -> &str {
        match self {
            Self::Root(root) => root,
            Self::Pattern { base, .. } => base,
        }
    }

    fn suffix(&self) -> &str {
        match self {
            Self::Root(_) => "",
            Self::Pattern { base, pattern, .. } => pattern[base.len()..].trim_start_matches('/'),
        }
    }

    fn is_recursive(&self) -> bool {
        self.suffix().contains("**")
    }

    fn covers(&self, path: &str) -> bool {
        match self {
            Self::Root(root) => path.is_under(root),
            Self::Pattern { matcher, .. } => path.lineage().any(|part| matcher.is_match(part)),
        }
    }

    /// Mirrors `has_unexcused_under`: the rule starts inside `dir`, or one
    /// of the tree's paths inside `dir` matches it and `is_denied`.
    fn has_under(&self, tree: &SandboxState, dir: &str, is_denied: impl Fn(&str) -> bool) -> bool {
        match self {
            Self::Root(root) => root.is_under(dir) && is_denied(root),
            Self::Pattern { base, matcher, .. } => {
                base.is_under(dir)
                    || (dir.is_under(base)
                        && tree.nodes.keys().any(|node| {
                            node.is_under(dir) && matcher.is_match(node.as_str()) && is_denied(node)
                        }))
            }
        }
    }

    /// An allow overrides a deny when it is at least as specific.
    fn overrides(&self, deny: &Self) -> bool {
        match (self, deny) {
            (Self::Root(allow), Self::Root(_)) => allow.is_under(deny.base()),
            (Self::Root(allow), Self::Pattern { .. }) => deny.covers(allow),
            (Self::Pattern { base, .. }, Self::Root(deny)) => base.is_under(deny),
            (
                Self::Pattern {
                    base: allow_base,
                    pattern: allow,
                    ..
                },
                Self::Pattern {
                    base: deny_base,
                    pattern: deny_pattern,
                    ..
                },
            ) => {
                if allow_base == deny_base {
                    allow == deny_pattern
                        || (!self.is_recursive() && deny.is_recursive())
                        || allow.len() >= deny_pattern.len()
                } else {
                    allow_base.is_strictly_under(deny_base)
                }
            }
        }
    }
}

/// One selector after resolution: concrete roots, glob spellings, the
/// existing paths a glob matches, and the literal path a bare glob falls back
/// to when it matches nothing.
#[derive(Default)]
struct Lowered {
    roots: Vec<Rule>,
    patterns: Vec<Rule>,
    matches: Vec<Rule>,
    fallback: Vec<Rule>,
}

#[derive(Default)]
struct RuleSet {
    roots: Vec<Rule>,
    patterns: Vec<Rule>,
}

impl RuleSet {
    fn rules(&self) -> impl Iterator<Item = &Rule> {
        self.roots.iter().chain(&self.patterns)
    }

    fn covers(&self, path: &str) -> bool {
        self.rules().any(|rule| rule.covers(path))
    }

    fn covers_either(&self, entry: &Entry) -> bool {
        self.covers(&entry.label) || self.covers(&entry.lexical)
    }
}

struct Lowering<'a> {
    tree: &'a SandboxState,
}

impl Lowering<'_> {
    fn join(base: &str, rel: &str) -> String {
        if base.is_empty() {
            rel.to_owned()
        } else {
            format!("{base}/{rel}")
        }
    }

    fn roots(&self, rel: &str) -> Vec<Rule> {
        let canonical = self.tree.canonical(rel);
        if cfg!(target_os = "macos") {
            let mut out = vec![Rule::Root(rel.to_owned())];
            if let Some(canonical) = canonical
                && canonical != rel
            {
                out.push(Rule::Root(canonical));
            }
            out
        } else {
            canonical.into_iter().map(Rule::Root).collect()
        }
    }

    fn glob(&self, rel: &str) -> Result<Lowered, TestCaseError> {
        let lexical = Rule::pattern(rel.to_owned())?;
        let matches = match &lexical {
            Rule::Pattern { base, matcher, .. } => self
                .tree
                .nodes
                .keys()
                .filter(|node| node.is_under(base) && matcher.is_match(node.as_str()))
                .flat_map(|node| self.roots(node))
                .collect(),
            Rule::Root(_) => Vec::new(),
        };
        let fallback = if matches!(self.tree.resolve(rel, false), ResolvedTarget::Node { .. }) {
            self.roots(rel)
        } else {
            Vec::new()
        };
        let mut patterns = Vec::new();
        if let Some(canonical) = self
            .tree
            .canonical(lexical.base())
            .filter(|canonical| canonical != lexical.base())
        {
            patterns.push(Rule::pattern(Self::join(&canonical, lexical.suffix()))?);
        }
        patterns.insert(0, lexical);
        Ok(Lowered {
            roots: Vec::new(),
            patterns,
            matches,
            fallback,
        })
    }

    fn at(&self, selector: &Selector, rel: &str) -> Result<Lowered, TestCaseError> {
        if selector.is_glob() {
            self.glob(rel)
        } else {
            Ok(Lowered {
                roots: self.roots(rel),
                ..Lowered::default()
            })
        }
    }

    /// Relative selectors resolve against the policy file's directory,
    /// which is outside the modelled tree.
    fn lower(&self, selector: &Selector) -> Result<Lowered, TestCaseError> {
        match selector.base {
            SelectorBase::Root | SelectorBase::Home => self.at(selector, &selector.rel),
            SelectorBase::Relative => Ok(Lowered::default()),
        }
    }

    fn deny(&self, selectors: &BTreeSet<Selector>, expand: bool) -> Result<RuleSet, TestCaseError> {
        let mut set = RuleSet::default();
        for selector in selectors {
            let lowered = self.lower(selector)?;
            set.roots.extend(lowered.roots);
            if expand {
                set.roots.extend(lowered.matches);
            }
            set.patterns.extend(lowered.patterns);
        }
        Ok(set)
    }

    /// `whole_tree` is set when `/` is granted alongside `selectors`; it
    /// covers every recursive glob, so those are not expanded.
    fn allow(
        &self,
        selectors: &BTreeSet<Selector>,
        whole_tree: bool,
    ) -> Result<RuleSet, TestCaseError> {
        let lowered = selectors
            .iter()
            .map(|selector| self.lower(selector))
            .collect::<Result<Vec<_>, _>>()?;
        let mut set = RuleSet::default();
        let mut globs = Vec::new();
        for lowered in lowered {
            set.roots.extend(lowered.roots);
            if !lowered.patterns.is_empty() {
                globs.push((lowered.patterns, lowered.matches, lowered.fallback));
            }
        }
        for (patterns, matches, fallback) in globs {
            let covered = patterns[0].is_recursive()
                && (whole_tree
                    || set
                        .roots
                        .iter()
                        .any(|root| patterns[0].base().is_under(root.base())));
            if !covered && !matches.is_empty() {
                set.roots.extend(matches);
            } else if !fallback.is_empty() {
                set.roots.extend(fallback);
                continue;
            }
            set.patterns.extend(patterns);
        }
        Ok(set)
    }

    /// The paths a selector names in the tree, with relative selectors
    /// joined to every write root that is a directory.
    fn spellings(&self, selector: &Selector, anchors: &[String]) -> Vec<String> {
        match selector.base {
            SelectorBase::Root | SelectorBase::Home => vec![selector.rel.clone()],
            SelectorBase::Relative => anchors
                .iter()
                .filter(|anchor| self.is_dir(anchor))
                .map(|anchor| Self::join(anchor, &selector.rel))
                .collect(),
        }
    }

    /// `denyWrite` selectors that are relative also apply under every
    /// write root that is a directory.
    fn anchored(
        &self,
        selectors: &BTreeSet<Selector>,
        anchors: &[String],
        expand: bool,
    ) -> Result<RuleSet, TestCaseError> {
        let mut set = self.deny(selectors, expand)?;
        for selector in selectors {
            if selector.base != SelectorBase::Relative {
                continue;
            }
            for rel in self.spellings(selector, anchors) {
                let lowered = self.at(selector, &rel)?;
                set.roots.extend(lowered.roots);
                if expand {
                    set.roots.extend(lowered.matches);
                }
                set.patterns.extend(lowered.patterns);
            }
        }
        Ok(set)
    }

    /// Mirrors `SymlinkAncestorCollector`: every symlink on the way to a
    /// selector's path, or to a glob's literal base, is denied too, under
    /// its requested spelling and below its parent's canonical path.
    fn denied_links(
        &self,
        selectors: &BTreeSet<Selector>,
        anchors: &[String],
        tier: Decision,
        links: &mut BTreeMap<String, Decision>,
    ) {
        for selector in selectors {
            for rel in self.spellings(selector, anchors) {
                let path = if selector.is_glob() {
                    Rule::literal_base(&rel)
                } else {
                    rel
                };
                let mut prefix = String::new();
                for part in path.split('/') {
                    prefix = Self::join(&prefix, part);
                    let ResolvedTarget::Node { kind, .. } = self.tree.resolve(&prefix, false)
                    else {
                        continue;
                    };
                    if kind.symlink_target().is_none() {
                        continue;
                    }
                    let (parent, name) = prefix.rsplit_once('/').unwrap_or(("", &prefix));
                    let canonical = self
                        .tree
                        .canonical(parent)
                        .map(|parent| Self::join(&parent, name));
                    for spelling in canonical.into_iter().chain([prefix.clone()]) {
                        let entry = links.entry(spelling).or_insert(tier);
                        if tier == Decision::Always {
                            *entry = tier;
                        }
                    }
                }
            }
        }
    }

    /// The tree has no node for the root itself, `""`.
    fn is_dir(&self, rel: &str) -> bool {
        rel.is_empty()
            || matches!(
                self.tree.resolve(rel, true),
                ResolvedTarget::Node {
                    kind: NodeKind::Dir { .. },
                    ..
                }
            )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadScope {
    Everything,
    OutsideDenied,
    GrantedOnly,
}

struct AccessRules {
    always: RuleSet,
    deny: RuleSet,
    grants: Vec<Rule>,
    carveouts: Vec<Rule>,
}

impl AccessRules {
    fn carveouts(patterns: Vec<Rule>, deny: &RuleSet) -> Vec<Rule> {
        patterns
            .into_iter()
            .filter(|allow| deny.rules().any(|rule| allow.overrides(rule)))
            .collect()
    }

    fn denial(&self, path: &str) -> Option<Decision> {
        if self.always.covers(path) {
            Some(Decision::Always)
        } else {
            self.soft_denied(path).then_some(Decision::DenyMatch)
        }
    }

    fn soft_denied(&self, path: &str) -> bool {
        let carved = |deny: &Rule| {
            self.grants
                .iter()
                .chain(&self.carveouts)
                .any(|allow| allow.overrides(deny) && allow.covers(path))
        };
        self.deny
            .rules()
            .any(|rule| rule.covers(path) && !carved(rule))
    }

    fn always_under(&self, tree: &SandboxState, dir: &str) -> bool {
        self.always
            .rules()
            .any(|rule| rule.has_under(tree, dir, |_| true))
    }

    /// Mirrors `DenialScope::has_denied_under`. A deny glob that is also a
    /// carveout denies nothing below `dir`.
    fn denied_under(&self, tree: &SandboxState, dir: &str) -> bool {
        let carveout = |rule: &Rule| match rule {
            Rule::Pattern { pattern, .. } => self.carveouts.iter().any(
                |allow| matches!(allow, Rule::Pattern { pattern: other, .. } if other == pattern),
            ),
            Rule::Root(_) => false,
        };
        self.always_under(tree, dir)
            || self.deny.rules().any(|rule| {
                !carveout(rule) && rule.has_under(tree, dir, |path| self.soft_denied(path))
            })
    }

    fn granted(&self, path: &str) -> bool {
        self.grants
            .iter()
            .chain(&self.carveouts)
            .any(|rule| rule.covers(path))
    }
}

/// A name the broker checks: `label` is its canonical path, without the
/// final symlink when the syscall does not follow it, and `lexical` the path
/// as requested.
#[derive(Debug, Clone)]
pub struct Entry {
    pub label: String,
    pub lexical: String,
}

/// What a brokered mutation does to names. A removal or a reparent can take
/// a denied path out of the policy's reach; a plain mutation creates a name
/// or rewrites an existing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(target_os = "linux"),
    expect(dead_code, reason = "only Linux brokers removals and reparents")
)]
pub enum Mutation {
    Removal,
    Reparent,
    Plain,
}

pub struct FsOracle {
    read: AccessRules,
    read_scope: ReadScope,
    read_denied_roots: Vec<Rule>,
    write: AccessRules,
    denied_links: BTreeMap<String, Decision>,
}

impl FsOracle {
    pub fn new(policy: &PolicyModel, tree: &SandboxState) -> Result<Self, TestCaseError> {
        let lowering = Lowering { tree };
        let (read, read_scope, read_denied_roots) = Self::read_rules(&lowering, policy)?;
        let (write, denied_links) = Self::write_rules(&lowering, policy)?;
        Ok(Self {
            read,
            read_scope,
            read_denied_roots,
            write,
            denied_links,
        })
    }

    fn read_rules(
        lowering: &Lowering<'_>,
        policy: &PolicyModel,
    ) -> Result<(AccessRules, ReadScope, Vec<Rule>), TestCaseError> {
        let allow = lowering.allow(
            &policy.allow_read,
            policy.read_base.allows_root(&policy.allow_read),
        )?;
        let deny = lowering.deny(&policy.deny_read, true)?;
        let always = lowering.deny(&policy.deny_read_always, true)?;
        let carveouts = if policy.read_base == ReadBase::Restricted {
            allow.patterns
        } else {
            AccessRules::carveouts(allow.patterns, &deny)
        };
        let uncarved = deny
            .roots
            .iter()
            .filter(|rule| {
                !allow
                    .roots
                    .iter()
                    .any(|grant| grant.base().is_under(rule.base()))
            })
            .cloned()
            .collect();
        let grants: Vec<Rule> = allow
            .roots
            .into_iter()
            .filter(|grant| !always.covers(grant.base()))
            .collect();
        let denied_roots: Vec<Rule> = deny.roots.iter().chain(&always.roots).cloned().collect();
        let scope = if policy.read_base == ReadBase::Restricted {
            ReadScope::GrantedOnly
        } else if denied_roots.is_empty()
            || (policy.read_base.allows_root(&policy.allow_read)
                && !grants.iter().any(|grant| {
                    denied_roots
                        .iter()
                        .any(|deny| grant.base().is_strictly_under(deny.base()))
                }))
        {
            ReadScope::Everything
        } else {
            ReadScope::OutsideDenied
        };
        let rules = AccessRules {
            always,
            deny: RuleSet {
                roots: uncarved,
                patterns: deny.patterns,
            },
            grants,
            carveouts,
        };
        Ok((rules, scope, denied_roots))
    }

    fn write_rules(
        lowering: &Lowering<'_>,
        policy: &PolicyModel,
    ) -> Result<(AccessRules, BTreeMap<String, Decision>), TestCaseError> {
        let allow = lowering.allow(&policy.allow_write, false)?;
        let mut anchors: Vec<String> = allow.rules().map(|rule| rule.base().to_owned()).collect();
        let always = lowering.anchored(&policy.deny_write_always, &anchors, true)?;
        let mut links = BTreeMap::new();
        lowering.denied_links(
            &policy.deny_write_always,
            &anchors,
            Decision::Always,
            &mut links,
        );
        anchors.retain(|anchor| !always.covers(anchor));
        lowering.denied_links(
            &policy.deny_write,
            &anchors,
            Decision::DenyMatch,
            &mut links,
        );
        let grants: Vec<Rule> = allow
            .roots
            .into_iter()
            .filter(|grant| !always.covers(grant.base()))
            .collect();
        let mut deny = lowering.anchored(&policy.deny_write, &anchors, false)?;
        let carved: Vec<String> = grants
            .iter()
            .filter(|grant| deny.covers(grant.base()))
            .map(|grant| grant.base().to_owned())
            .collect();
        deny.roots
            .retain(|rule| !carved.iter().any(|root| root == rule.base()));
        let rules = AccessRules {
            carveouts: AccessRules::carveouts(allow.patterns, &deny),
            always,
            deny,
            grants,
        };
        Ok((rules, links))
    }

    /// `lexical` is the path as requested, before symlinks are resolved.
    /// Hard denies apply to either spelling; ordinary denies of the
    /// requested spelling only once the canonical path is readable.
    pub fn read(&self, canonical: &str, lexical: &str) -> Decision {
        let lexical_denial = (cfg!(target_os = "linux") && lexical != canonical)
            .then(|| self.read.denial(lexical))
            .flatten();
        if lexical_denial == Some(Decision::Always) {
            return Decision::Always;
        }
        if let Some(decision) = self.read.denial(canonical) {
            return decision;
        }
        let granted = match self.read_scope {
            ReadScope::Everything => true,
            ReadScope::OutsideDenied => {
                !self
                    .read_denied_roots
                    .iter()
                    .any(|rule| rule.covers(canonical))
                    || self.read.granted(canonical)
            }
            ReadScope::GrantedOnly => self.read.granted(canonical),
        };
        if !granted {
            return Decision::AllowMiss;
        }
        lexical_denial.unwrap_or(Decision::Allow)
    }

    /// Whether macOS Seatbelt permits `file-read-metadata` (`readlink`) on
    /// `link`. Seatbelt's `read_rules` allows `file-read*` on grants and
    /// carveouts and `file-read-metadata` on symlinks outside denied roots
    /// (`RootScan`), applies soft `read_denials`, grants `file-read-metadata`
    /// on strict ancestors of grant and carveout bases (`parent_dir_rules`),
    /// and finishes with `always` denials.
    pub fn can_read_symlink(&self, link: &str) -> bool {
        if self.read.always.covers(link) {
            return false;
        }
        let ancestor_of_grant = || {
            self.read
                .grants
                .iter()
                .chain(&self.read.carveouts)
                .any(|rule| rule.base().is_strictly_under(link))
        };
        if ancestor_of_grant() {
            return true;
        }
        if self.read.denial(link).is_some() {
            return false;
        }
        match self.read_scope {
            ReadScope::Everything => true,
            ReadScope::OutsideDenied => {
                !self.read_denied_roots.iter().any(|rule| rule.covers(link))
                    || self.read.granted(link)
            }
            ReadScope::GrantedOnly => self.read.granted(link),
        }
    }

    /// Writes are decided on `canonical`. A hard deny of the requested
    /// spelling, `lexical`, only keeps a denial from the responder.
    pub fn write(&self, canonical: &str, lexical: &str) -> Decision {
        let decision = match self.write.denial(canonical) {
            Some(decision) => decision,
            None if self.write.granted(canonical) => Decision::Allow,
            None => Decision::AllowMiss,
        };
        let lexical_always =
            lexical != canonical && self.write.denial(lexical) == Some(Decision::Always);
        if decision != Decision::Allow && lexical_always {
            Decision::Always
        } else {
            decision
        }
    }

    /// Mirrors the broker's mutation check. Hard denials of either spelling
    /// come first and are never offered to the responder. A removal or
    /// reparent also needs the old name to be outside every denied symlink
    /// ancestor and readable, so that no denied path escapes the policy
    /// under a new name.
    pub fn mutation(&self, tree: &SandboxState, mutation: Mutation, entries: &[Entry]) -> Decision {
        let renames = mutation != Mutation::Plain;
        let reparent = mutation == Mutation::Reparent;
        let Some(source) = entries.first() else {
            return Decision::Allow;
        };
        let link = renames
            .then(|| {
                let always = entries.iter().find_map(|entry| {
                    self.denied_links
                        .get(&entry.lexical)
                        .filter(|&&tier| tier == Decision::Always)
                        .or_else(|| {
                            self.denied_links
                                .get(&entry.label)
                                .filter(|&&tier| tier == Decision::Always)
                        })
                });
                always.or_else(|| {
                    entries.iter().find_map(|entry| {
                        self.denied_links
                            .get(&entry.lexical)
                            .or_else(|| self.denied_links.get(&entry.label))
                    })
                })
            })
            .flatten();
        let hard = entries.iter().any(|entry| {
            (renames
                && (self.read.always.covers_either(entry)
                    || self.read.always_under(tree, &entry.label)))
                || self.write.always.covers_either(entry)
                || (reparent && self.write.always_under(tree, &entry.label))
        });
        if hard || link == Some(&Decision::Always) {
            return Decision::Always;
        }
        let write = entries
            .iter()
            .find_map(|entry| match self.write(&entry.label, &entry.label) {
                Decision::Allow => (reparent && self.write.denied_under(tree, &entry.label))
                    .then_some(Decision::DenyMatch),
                decision => Some(decision),
            });
        let unreadable = |entry: &Entry| match self.read(&entry.label, &entry.label) {
            Decision::Allow => self
                .read
                .denied_under(tree, &entry.label)
                .then_some(Decision::DenyMatch),
            decision => Some(decision),
        };
        let name = match (mutation, entries.get(1)) {
            (Mutation::Removal, _) => (self.read.denial(&source.label).is_some()
                || self.read.denial(&source.lexical).is_some())
            .then_some(Decision::DenyMatch),
            (Mutation::Reparent, Some(dest)) => unreadable(source).or_else(|| unreadable(dest)),
            _ => None,
        };
        write.or(link.copied()).or(name).unwrap_or(Decision::Allow)
    }

    pub fn read_denied_under(&self, tree: &SandboxState, prefix: &str) -> bool {
        tree.nodes
            .keys()
            .filter(|rel| rel.is_under(prefix))
            .any(|rel| self.read(rel, rel) != Decision::Allow)
    }
}

impl SandboxState {
    pub fn oracle(&self) -> Result<FsOracle, TestCaseError> {
        FsOracle::new(&self.policy, self)
    }
}
