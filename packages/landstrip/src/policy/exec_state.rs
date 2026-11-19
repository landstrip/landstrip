// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! A lossless encoding of lowered rules for a native KVM broker restart.
//!
//! The CLI's policy representation is for display. In particular, it does
//! not distinguish system sockets from session buses, and a printed glob
//! does not identify its literal base. A restart must not lower policy again.

use super::{
    AccessPolicy, AppContainerMode, Carveouts, DenialScope, DenialTier, DeniedLink, DeniedLinks,
    GlobPattern, IpBindAccess, NetworkAccess, ReadAccess, SandboxDarwin, SessionBus,
    SupervisorSocketSet, UnixSocketAccess,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

#[derive(Deserialize, Serialize)]
pub(crate) struct Rules {
    write_roots: Vec<OsString>,
    write_denials: Denials,
    write_denied_links: Vec<(OsString, bool)>,
    read_access: SavedRead,
    read_denials: Denials,
    read_symlinks: Vec<OsString>,
    network: Network,
    supervisor_paths: Vec<OsString>,
    system_sockets: Vec<OsString>,
    session_buses: Vec<(OsString, bool)>,
    macos: SandboxDarwin,
    app_container_mode: AppContainerMode,
    allow_windows_loopback: bool,
    allow_windows_additive_grants: bool,
}

#[derive(Deserialize, Serialize)]
enum SavedRead {
    Unrestricted,
    AllowRoots(Vec<OsString>),
    OutsideDenied {
        denied_roots: Vec<OsString>,
        allow_roots: Vec<OsString>,
    },
}

#[derive(Deserialize, Serialize)]
struct Denials {
    roots: Vec<OsString>,
    patterns: Vec<(OsString, String)>,
    carveout_roots: Vec<OsString>,
    carveout_patterns: Vec<(OsString, String)>,
    always_roots: Vec<OsString>,
    always_patterns: Vec<(OsString, String)>,
}

#[derive(Deserialize, Serialize)]
struct Network {
    ip: Option<Ip>,
    unix: Unix,
}

#[derive(Deserialize, Serialize)]
struct Ip {
    connect: Vec<u16>,
    bind_localhost: bool,
}

#[derive(Deserialize, Serialize)]
enum Unix {
    Unrestricted,
    AllowPaths(Vec<OsString>),
    Denied,
}

fn save_paths(paths: &[PathBuf]) -> Vec<OsString> {
    paths
        .iter()
        .map(|path| path.as_os_str().to_owned())
        .collect()
}

fn load_paths(paths: Vec<OsString>) -> Vec<PathBuf> {
    paths.into_iter().map(PathBuf::from).collect()
}

fn save_patterns(patterns: &[GlobPattern]) -> Vec<(OsString, String)> {
    patterns.iter().map(GlobPattern::exec_parts).collect()
}

fn load_patterns(patterns: Vec<(OsString, String)>) -> Result<Vec<GlobPattern>> {
    patterns
        .into_iter()
        .map(|(base, suffix)| {
            GlobPattern::from_exec_parts(Path::new(&base), &suffix).map_err(Into::into)
        })
        .collect()
}

impl Denials {
    fn save(scope: &DenialScope) -> Self {
        Self {
            roots: save_paths(&scope.roots),
            patterns: save_patterns(&scope.patterns),
            carveout_roots: save_paths(&scope.carveouts.roots),
            carveout_patterns: save_patterns(&scope.carveouts.patterns),
            always_roots: save_paths(&scope.always_roots),
            always_patterns: save_patterns(&scope.always_patterns),
        }
    }

    fn restore(self) -> Result<DenialScope> {
        Ok(DenialScope {
            roots: load_paths(self.roots),
            patterns: load_patterns(self.patterns)?,
            carveouts: Carveouts {
                roots: load_paths(self.carveout_roots),
                patterns: load_patterns(self.carveout_patterns)?,
            },
            always_roots: load_paths(self.always_roots),
            always_patterns: load_patterns(self.always_patterns)?,
        })
    }
}

impl Network {
    fn save(access: &NetworkAccess) -> Self {
        let unix = match access.unix_socket_access() {
            UnixSocketAccess::Unrestricted => Unix::Unrestricted,
            UnixSocketAccess::AllowPaths(paths) => Unix::AllowPaths(save_paths(paths)),
            UnixSocketAccess::Denied => Unix::Denied,
        };
        let ip = match access {
            NetworkAccess::Unrestricted { .. } => None,
            NetworkAccess::Restricted {
                connect_tcp_ports,
                bind,
                ..
            } => Some(Ip {
                connect: connect_tcp_ports.clone(),
                bind_localhost: *bind == IpBindAccess::Localhost,
            }),
        };
        Self { ip, unix }
    }

    fn restore(self) -> NetworkAccess {
        let unix_socket_access = match self.unix {
            Unix::Unrestricted => UnixSocketAccess::Unrestricted,
            Unix::AllowPaths(paths) => UnixSocketAccess::AllowPaths(load_paths(paths)),
            Unix::Denied => UnixSocketAccess::Denied,
        };
        match self.ip {
            None => NetworkAccess::Unrestricted { unix_socket_access },
            Some(ip) => NetworkAccess::Restricted {
                connect_tcp_ports: ip.connect,
                bind: if ip.bind_localhost {
                    IpBindAccess::Localhost
                } else {
                    IpBindAccess::Deny
                },
                unix_socket_access,
            },
        }
    }
}

impl Rules {
    pub(crate) fn save(policy: &AccessPolicy) -> Self {
        let sockets = &policy.supervisor_sockets;
        Self {
            write_roots: save_paths(&policy.write_roots),
            write_denials: Denials::save(&policy.write_denials),
            write_denied_links: policy
                .write_denied_links
                .iter()
                .map(|link| {
                    (
                        link.path.as_os_str().to_owned(),
                        link.tier == DenialTier::Always,
                    )
                })
                .collect(),
            read_access: match &policy.read_access {
                ReadAccess::Unrestricted => SavedRead::Unrestricted,
                ReadAccess::AllowRoots(roots) => SavedRead::AllowRoots(save_paths(roots)),
                ReadAccess::OutsideDenied {
                    denied_roots,
                    allow_roots,
                } => SavedRead::OutsideDenied {
                    denied_roots: save_paths(denied_roots),
                    allow_roots: save_paths(allow_roots),
                },
            },
            read_denials: Denials::save(&policy.read_denials),
            read_symlinks: save_paths(&policy.read_symlinks),
            network: Network::save(&policy.network_access),
            supervisor_paths: save_paths(&sockets.all),
            system_sockets: save_paths(&sockets.system),
            session_buses: sockets
                .session_buses
                .iter()
                .map(|bus| (bus.path.as_os_str().to_owned(), bus.allowed))
                .collect(),
            macos: policy.macos.clone(),
            app_container_mode: policy.app_container_mode,
            allow_windows_loopback: policy.allow_windows_loopback,
            allow_windows_additive_grants: policy.allow_windows_additive_grants,
        }
    }

    pub(crate) fn restore(self) -> Result<AccessPolicy> {
        Ok(AccessPolicy {
            write_roots: load_paths(self.write_roots),
            write_denials: self.write_denials.restore()?,
            write_denied_links: DeniedLinks::new(
                self.write_denied_links
                    .into_iter()
                    .map(|(path, always)| {
                        DeniedLink::new(
                            path.into(),
                            if always {
                                DenialTier::Always
                            } else {
                                DenialTier::Queryable
                            },
                        )
                    })
                    .collect(),
            ),
            read_access: match self.read_access {
                SavedRead::Unrestricted => ReadAccess::Unrestricted,
                SavedRead::AllowRoots(roots) => ReadAccess::AllowRoots(load_paths(roots)),
                SavedRead::OutsideDenied {
                    denied_roots,
                    allow_roots,
                } => ReadAccess::OutsideDenied {
                    denied_roots: load_paths(denied_roots),
                    allow_roots: load_paths(allow_roots),
                },
            },
            read_denials: self.read_denials.restore()?,
            read_symlinks: load_paths(self.read_symlinks),
            network_access: self.network.restore(),
            supervisor_sockets: SupervisorSocketSet {
                all: load_paths(self.supervisor_paths),
                system: load_paths(self.system_sockets),
                session_buses: self
                    .session_buses
                    .into_iter()
                    .map(|(path, allowed)| SessionBus {
                        path: path.into(),
                        allowed,
                    })
                    .collect(),
            },
            macos: self.macos,
            app_container_mode: self.app_container_mode,
            allow_windows_loopback: self.allow_windows_loopback,
            allow_windows_additive_grants: self.allow_windows_additive_grants,
        })
    }
}
