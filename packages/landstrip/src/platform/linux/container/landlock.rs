// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::error::{Error, PathIo};
use crate::policy::AccessPolicy;
use anyhow::{Context, Result};
use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, Erratum, LandlockStatus,
    NetPort, PathBeneath, Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus,
    Scope,
};
use nix::fcntl::{OFlag, open};
use nix::sys::stat::{Mode, fstat};
use std::io;
use std::os::fd::OwnedFd;
use std::path::PathBuf;

const TARGET_ABI: ABI = ABI::V7;

pub(super) struct LandlockRuleset {
    created: RulesetCreated,
    handled_access_net: BitFlags<AccessNet>,
}

impl TryFrom<&AccessPolicy> for LandlockRuleset {
    type Error = Error;

    fn try_from(policy: &AccessPolicy) -> std::result::Result<Self, Self::Error> {
        let mut handled_access_net = BitFlags::<AccessNet>::empty();
        if policy.network_access.restricts_connect_tcp() {
            handled_access_net |= AccessNet::ConnectTcp;
        }
        if policy.network_access.restricts_bind_ip() {
            handled_access_net |= AccessNet::BindTcp;
        }

        let mut ruleset = Ruleset::default()
            .handle_access(AccessFs::from_write(TARGET_ABI))
            .map_err(Error::landlock)?;
        if !handled_access_net.is_empty() {
            ruleset = ruleset
                .handle_access(handled_access_net)
                .map_err(Error::landlock)?;
        }
        ruleset = ruleset
            .scope(Scope::AbstractUnixSocket | Scope::Signal)
            .map_err(Error::landlock)?;
        let mut created = ruleset.create().map_err(Error::landlock)?;

        created = Self::add_path_rules(created, &policy.write_roots)?;

        if !handled_access_net.is_empty() {
            created = Self::add_network_rules(created, policy)?;
        }

        Ok(Self {
            created,
            handled_access_net,
        })
    }
}

impl LandlockRuleset {
    pub(super) fn probe() -> Result<()> {
        Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::Execute)
            .context("Landlock execute access is unavailable")?
            .create()
            .context("create a Landlock ruleset")?;
        Ok(())
    }

    pub(super) fn enforce(self) -> Result<()> {
        let Self {
            created,
            handled_access_net,
        } = self;
        let status = created.restrict_self().map_err(Error::landlock)?;
        match status.ruleset {
            RulesetStatus::FullyEnforced => {}
            RulesetStatus::PartiallyEnforced => log::debug!(
                "{}",
                Self::partial_enforcement_warning(status.landlock, handled_access_net)
            ),
            RulesetStatus::NotEnforced => {
                return Err(Error::landlock(
                    "not enforced by the kernel (Linux 5.13+ with CONFIG_SECURITY_LANDLOCK required, \
                     and not disabled via the lsm= boot parameter)",
                )
                .into());
            }
        }
        if !Erratum::current().contains(Erratum::ScopedSignalHandling) {
            log::debug!(
                "landlock: kernel has not fixed scoped signal handling (erratum 2); threads that \
                 apply Landlock independently in one process may be unable to signal each other"
            );
        }

        Ok(())
    }

    fn partial_enforcement_warning(
        status: LandlockStatus,
        handled_access_net: BitFlags<AccessNet>,
    ) -> String {
        let LandlockStatus::Available { effective_abi, .. } = status else {
            return "landlock: kernel only partially enforced the policy".to_owned();
        };
        let supported_fs = AccessFs::from_all(effective_abi);
        let supported_net = AccessNet::from_all(effective_abi);
        let mut missing = Vec::new();
        for (access, name) in [
            (AccessFs::Refer, "filesystem REFER"),
            (AccessFs::Truncate, "filesystem TRUNCATE"),
            (AccessFs::IoctlDev, "filesystem IOCTL_DEV"),
        ] {
            if !supported_fs.contains(access) {
                missing.push(name);
            }
        }
        for (access, name) in [
            (AccessNet::BindTcp, "network BIND_TCP"),
            (AccessNet::ConnectTcp, "network CONNECT_TCP"),
        ] {
            if handled_access_net.contains(access) && !supported_net.contains(access) {
                missing.push(name);
            }
        }
        let supported_scope = Scope::from_all(effective_abi);
        if !supported_scope.contains(Scope::AbstractUnixSocket) {
            missing.push("scope ABSTRACT_UNIX_SOCKET");
        }
        if !supported_scope.contains(Scope::Signal) {
            missing.push("scope SIGNAL");
        }

        let details = if missing.is_empty() {
            "some requested features".to_owned()
        } else {
            missing.join(", ")
        };
        format!(
            "landlock: kernel ABI {effective_abi} only partially enforced the policy; unsupported \
             access rights: {details}; supported rights remain enforced; Landlock ABI 6 or newer \
             (upstream Linux 6.12+) is required for complete enforcement"
        )
    }

    fn add_path_rules(
        mut ruleset: RulesetCreated,
        paths: &[PathBuf],
    ) -> std::result::Result<RulesetCreated, Error> {
        let access = AccessFs::from_write(TARGET_ABI);
        for path in paths {
            let fd = match open(path, OFlag::O_PATH | OFlag::O_CLOEXEC, Mode::empty())
                .map_err(io::Error::from)
            {
                Ok(fd) => fd,
                Err(error) if error.is_opaque() => {
                    log::debug!(
                        "landlock: write {} unreachable, skipping parent grant: {error}",
                        path.display()
                    );
                    continue;
                }
                Err(error) => return Err(Error::landlock(error)),
            };

            let path_access = if Self::fd_is_dir(&fd)? {
                access
            } else {
                access & AccessFs::from_file(TARGET_ABI)
            };
            if path_access.is_empty() {
                continue;
            }

            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, path_access))
                .map_err(Error::landlock)?;
        }

        Ok(ruleset)
    }

    fn add_network_rules(
        mut ruleset: RulesetCreated,
        policy: &AccessPolicy,
    ) -> std::result::Result<RulesetCreated, Error> {
        if !policy.network_access.restricts_connect_tcp() {
            return Ok(ruleset);
        }

        for port in policy.network_access.connect_tcp_ports() {
            ruleset = ruleset
                .add_rule(NetPort::new(*port, AccessNet::ConnectTcp))
                .map_err(Error::landlock)?;
        }

        Ok(ruleset)
    }

    fn fd_is_dir(fd: &OwnedFd) -> std::result::Result<bool, Error> {
        let stat = match fstat(fd).map_err(io::Error::from) {
            Ok(stat) => stat,
            Err(error) if error.is_transport_failed() => {
                return Ok(false);
            }
            Err(error) => return Err(Error::landlock(error)),
        };

        Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFDIR)
    }
}
