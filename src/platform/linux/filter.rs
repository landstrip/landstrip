// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Seccomp BPF filter construction.
//!
//! Lowers a network and filesystem policy into seccomp programs: an errno
//! filter that fails disallowed socket families outright and a user-notify
//! filter that traps the syscalls the broker mediates. This layer is pure
//! policy-to-program translation; it does not run the notification loop.

use super::seccomp::NotificationSyscalls;
use crate::engine::error::Error as LandstripError;
use crate::engine::policy::{AccessPolicy, ReadAccess, UnixSocketAccess};
use anyhow::{Result, anyhow};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};
use std::collections::BTreeMap;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::ptr;

const SOCK_TYPE_MASK: u64 = 0x0f;
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
const AUDIT_ARCH_RISCV64: u32 = 0xC000_00F3;

#[repr(C)]
struct SockFilterProg {
    len: libc::c_ushort,
    filter: *const seccompiler::sock_filter,
}

pub(super) type RuleMap = BTreeMap<i64, Vec<SeccompRule>>;

pub(super) fn build_errno_filter(
    syscalls: &NotificationSyscalls,
    needs_network: bool,
    unix_sockets: UnixSocketFilter,
) -> Result<Option<BpfProgram>> {
    let mut errno_rules = RuleMap::new();
    if needs_network {
        add_socket_family_filter(&mut errno_rules, syscalls.socket)?;
        add_unix_socket_filters(&mut errno_rules, syscalls.socket, unix_sockets)?;
    }
    if errno_rules.is_empty() {
        return Ok(None);
    }
    let eafnosupport =
        u32::try_from(libc::EAFNOSUPPORT).map_err(|_| LandstripError::IntegerTooLarge)?;
    build_filter(errno_rules, SeccompAction::Errno(eafnosupport)).map(Some)
}

pub(super) fn network_filter(config: NetworkFilter, needs_network: bool) -> Result<NetworkFilters> {
    let syscalls = NotificationSyscalls::new();
    let errno = build_errno_filter(&syscalls, needs_network, config.unix_sockets)?;
    let notify = if config.notify_bind || config.notify_connect || config.notify_filesystem {
        let mut notify_syscalls = Vec::new();
        if config.notify_bind {
            notify_syscalls.push(syscalls.bind);
        }
        if config.notify_connect {
            notify_syscalls.push(syscalls.connect);
        }
        if config.notify_filesystem {
            notify_syscalls.extend(syscalls.filesystem_syscalls());
        }
        Some(build_notify_filter(&notify_syscalls)?)
    } else {
        None
    };

    Ok(NetworkFilters { errno, notify })
}

pub(super) struct NetworkFilters {
    errno: Option<BpfProgram>,
    notify: Option<BpfProgram>,
}

impl NetworkFilters {
    pub(super) fn new(errno: Option<BpfProgram>, notify: Option<BpfProgram>) -> Self {
        Self { errno, notify }
    }

    pub(super) fn load(&self) -> Result<()> {
        if let Some(errno) = &self.errno {
            load_program(errno, 0)?;
        }
        if let Some(notify) = &self.notify {
            load_program(notify, 0)?;
        }

        Ok(())
    }

    pub(super) fn load_with_listener(&self) -> Result<OwnedFd> {
        if let Some(errno) = &self.errno {
            load_program(errno, 0)?;
        }
        let notify = self.notify.as_ref().ok_or_else(|| {
            LandstripError::IoFailed(io::Error::other("linux: notify filter missing"))
        })?;

        let listener = load_program(notify, libc::SECCOMP_FILTER_FLAG_NEW_LISTENER)?
            .ok_or_else(|| LandstripError::IoFailed(io::Error::other("linux: listener missing")))?;
        Ok(listener)
    }
}

pub(super) fn build_filter(rules: RuleMap, match_action: SeccompAction) -> Result<BpfProgram> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => Ok(TargetArch::x86_64),
        "aarch64" => Ok(TargetArch::aarch64),
        "riscv64" => Ok(TargetArch::riscv64),
        arch => Err(anyhow!("linux: unsupported target arch: {arch}")),
    }?;

    let filter = SeccompFilter::new(rules, SeccompAction::Allow, match_action, arch)
        .map_err(|source| anyhow!("linux: {source}"))?;
    let program = <BpfProgram as TryFrom<SeccompFilter>>::try_from(filter)
        .map_err(|source| anyhow!("linux: {source}"))?;

    Ok(program)
}

pub(super) fn build_notify_filter(syscalls: &[i64]) -> Result<BpfProgram> {
    let mut program = BpfProgram::with_capacity(syscalls.len() * 2 + 5);
    let load = bpf_code(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS)?;
    let jump_eq = bpf_code(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K)?;
    let ret = bpf_code(libc::BPF_RET | libc::BPF_K)?;

    let arch = match std::env::consts::ARCH {
        "x86_64" => Ok(AUDIT_ARCH_X86_64),
        "aarch64" => Ok(AUDIT_ARCH_AARCH64),
        "riscv64" => Ok(AUDIT_ARCH_RISCV64),
        arch => Err(anyhow!("linux: unsupported audit arch: {arch}")),
    }?;

    program.push(bpf_stmt(load, SECCOMP_DATA_ARCH_OFFSET));
    program.push(bpf_jump(jump_eq, arch, 1, 0));
    program.push(bpf_stmt(ret, libc::SECCOMP_RET_KILL_PROCESS));

    program.push(bpf_stmt(load, SECCOMP_DATA_NR_OFFSET));
    for syscall in syscalls {
        let syscall = u32::try_from(*syscall).map_err(|_| LandstripError::IntegerTooLarge)?;
        program.push(bpf_jump(jump_eq, syscall, 0, 1));
        program.push(bpf_stmt(ret, libc::SECCOMP_RET_USER_NOTIF));
    }
    program.push(bpf_stmt(ret, libc::SECCOMP_RET_ALLOW));

    Ok(program)
}

fn bpf_code(code: u32) -> Result<u16> {
    u16::try_from(code).map_err(|_| LandstripError::IntegerTooLarge.into())
}

fn bpf_stmt(code: u16, k: u32) -> seccompiler::sock_filter {
    seccompiler::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> seccompiler::sock_filter {
    seccompiler::sock_filter { code, jt, jf, k }
}

fn load_program(program: &BpfProgram, flags: libc::c_ulong) -> Result<Option<OwnedFd>> {
    if program.is_empty() {
        return Err(LandstripError::IoFailed(io::Error::other("linux: empty program")).into());
    }

    // SAFETY: prctl(2) copies scalar arguments only.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(LandstripError::IoFailed(io::Error::last_os_error()).into());
    }

    let len =
        libc::c_ushort::try_from(program.len()).map_err(|_| LandstripError::IntegerTooLarge)?;
    let filter = SockFilterProg {
        len,
        filter: program.as_ptr(),
    };

    // SAFETY: filter points to a live seccomp BPF program for the duration of the syscall.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            flags,
            ptr::addr_of!(filter),
        )
    };
    if rc < 0 {
        return Err(LandstripError::IoFailed(io::Error::last_os_error()).into());
    }

    if flags & libc::SECCOMP_FILTER_FLAG_NEW_LISTENER == 0 {
        return Ok(None);
    }

    let fd = RawFd::try_from(rc).map_err(|_| LandstripError::IntegerTooLarge)?;
    // SAFETY: seccomp returned a new listener fd when NEW_LISTENER was set.
    Ok(Some(unsafe { OwnedFd::from_raw_fd(fd) }))
}

fn seccomp_condition(
    arg_index: u8,
    operator: SeccompCmpOp,
    value: u64,
) -> Result<SeccompCondition> {
    SeccompCondition::new(arg_index, SeccompCmpArgLen::Dword, operator, value)
        .map_err(|source| anyhow!("linux: {source}"))
}

fn add_conditional_rule(
    rules: &mut RuleMap,
    syscall: i64,
    conditions: Vec<SeccompCondition>,
) -> Result<()> {
    let rule = SeccompRule::new(conditions).map_err(|source| anyhow!("linux: {source}"))?;
    rules.entry(syscall).or_default().push(rule);

    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
pub(super) fn add_unix_socket_filters(
    _rules: &mut RuleMap,
    _socket: i64,
    policy: UnixSocketFilter,
) -> Result<()> {
    // socket(AF_UNIX) creation is always allowed; denials happen at connect/bind
    // in the broker with EACCES. This unifies the DenyAll and PathMediated
    // paths and mirrors the macOS backend, which also allows creation.
    //
    // socketpair is unaffected: it carries no path and no remote address, so it
    // never reaches the broker's path authorization.
    let _ = policy;
    Ok(())
}

pub(super) fn needs_unix_socket_broker(access: &UnixSocketAccess) -> bool {
    matches!(access, UnixSocketAccess::AllowPaths(_))
}

pub(super) fn needs_filesystem_broker(policy: &AccessPolicy) -> bool {
    !policy.write_roots.is_empty() || !matches!(policy.read_access, ReadAccess::Unrestricted)
}

pub(super) fn unix_socket_filter(access: &UnixSocketAccess) -> UnixSocketFilter {
    match access {
        UnixSocketAccess::Unrestricted => UnixSocketFilter::Unrestricted,
        UnixSocketAccess::AllowPaths(paths) if paths.is_empty() => UnixSocketFilter::DenyAll,
        UnixSocketAccess::AllowPaths(_) => UnixSocketFilter::PathMediated,
    }
}

#[derive(Clone, Copy)]
pub(super) struct NetworkFilter {
    pub(super) notify_bind: bool,
    pub(super) notify_connect: bool,
    pub(super) notify_filesystem: bool,
    pub(super) unix_sockets: UnixSocketFilter,
}

#[derive(Clone, Copy)]
pub(super) enum UnixSocketFilter {
    Unrestricted,
    PathMediated,
    DenyAll,
}

pub(super) fn add_socket_family_filter(rules: &mut RuleMap, socket: i64) -> Result<()> {
    let stream = u64::try_from(libc::SOCK_STREAM).map_err(|_| LandstripError::IntegerTooLarge)?;
    let tcp = u64::try_from(libc::IPPROTO_TCP).map_err(|_| LandstripError::IntegerTooLarge)?;

    for domain in [libc::AF_INET, libc::AF_INET6] {
        let domain = u64::try_from(domain).map_err(|_| LandstripError::IntegerTooLarge)?;

        for ty in 0..=SOCK_TYPE_MASK {
            if ty == stream {
                continue;
            }

            add_conditional_rule(
                rules,
                socket,
                vec![
                    seccomp_condition(0, SeccompCmpOp::Eq, domain)?,
                    seccomp_condition(1, SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK), ty)?,
                ],
            )?;
        }

        for proto in 1..tcp {
            add_conditional_rule(
                rules,
                socket,
                vec![
                    seccomp_condition(0, SeccompCmpOp::Eq, domain)?,
                    seccomp_condition(1, SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK), stream)?,
                    seccomp_condition(2, SeccompCmpOp::Eq, proto)?,
                ],
            )?;
        }

        add_conditional_rule(
            rules,
            socket,
            vec![
                seccomp_condition(0, SeccompCmpOp::Eq, domain)?,
                seccomp_condition(1, SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK), stream)?,
                seccomp_condition(2, SeccompCmpOp::Gt, tcp)?,
            ],
        )?;
    }

    for domain in [libc::AF_PACKET, libc::AF_NETLINK] {
        add_socket_domain_filter(rules, socket, domain)?;
    }

    Ok(())
}

fn add_socket_domain_filter(rules: &mut RuleMap, socket: i64, domain: i32) -> Result<()> {
    let domain = u64::try_from(domain).map_err(|_| LandstripError::IntegerTooLarge)?;

    add_conditional_rule(
        rules,
        socket,
        vec![seccomp_condition(0, SeccompCmpOp::Eq, domain)?],
    )
}
