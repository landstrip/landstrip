// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Seccomp BPF filter construction.
//!
//! Lowers a network and filesystem policy into seccomp programs: an errno
//! filter that fails disallowed socket families outright and a user-notify
//! filter that traps the syscalls the broker mediates. This layer is pure
//! policy-to-program translation; it does not run the notification loop.

use crate::error::{Error as LandstripError, Mechanism};
use crate::policy::{AccessPolicy, UnixSocketAccess};
use anyhow::Result;
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
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

#[repr(C)]
struct SockFilterProg {
    len: libc::c_ushort,
    filter: *const seccompiler::sock_filter,
}

struct Architecture {
    target: TargetArch,
    audit: u32,
}

impl Architecture {
    fn current() -> Result<Self> {
        match std::env::consts::ARCH {
            "x86_64" => Ok(Self {
                target: TargetArch::x86_64,
                audit: AUDIT_ARCH_X86_64,
            }),
            "aarch64" => Ok(Self {
                target: TargetArch::aarch64,
                audit: AUDIT_ARCH_AARCH64,
            }),
            "riscv64" => Ok(Self {
                target: TargetArch::riscv64,
                audit: AUDIT_ARCH_RISCV64,
            }),
            arch => Err(LandstripError::sandbox_setup(
                Mechanism::Seccomp,
                format!("unsupported target arch: {arch}"),
            )
            .into()),
        }
    }
}

pub(super) type RuleMap = BTreeMap<i64, Vec<SeccompRule>>;

#[derive(Clone, Copy)]
pub(super) enum UnixSocketFilter {
    Unrestricted,
    PathMediated,
    DenyAll,
}

impl UnixSocketFilter {
    fn blocks_datagrams(self) -> bool {
        matches!(self, Self::DenyAll | Self::PathMediated)
    }
}

impl From<&UnixSocketAccess> for UnixSocketFilter {
    fn from(access: &UnixSocketAccess) -> Self {
        match access {
            UnixSocketAccess::Unrestricted => Self::Unrestricted,
            UnixSocketAccess::AllowPaths(_) => Self::PathMediated,
            UnixSocketAccess::Denied => Self::DenyAll,
        }
    }
}

pub(super) struct FilterBuilder {
    rules: RuleMap,
}

impl FilterBuilder {
    pub(super) fn new() -> Self {
        Self {
            rules: RuleMap::new(),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub(super) fn add_unconditional(&mut self, syscall: i64) {
        self.rules.entry(syscall).or_default();
    }

    fn add_conditional_rule(
        &mut self,
        syscall: i64,
        conditions: Vec<SeccompCondition>,
    ) -> Result<()> {
        let rule = SeccompRule::new(conditions)
            .map_err(|source| LandstripError::sandbox_setup(Mechanism::Seccomp, source))?;
        self.rules.entry(syscall).or_default().push(rule);
        Ok(())
    }

    pub(super) fn build(self, match_action: SeccompAction) -> Result<BpfProgram> {
        let arch = Architecture::current()?.target;
        let filter = SeccompFilter::new(self.rules, SeccompAction::Allow, match_action, arch)
            .map_err(|source| LandstripError::sandbox_setup(Mechanism::Seccomp, source))?;
        <BpfProgram as TryFrom<SeccompFilter>>::try_from(filter)
            .map_err(|source| LandstripError::sandbox_setup(Mechanism::Seccomp, source).into())
    }
}

pub(super) struct FilterSet {
    errno: Option<BpfProgram>,
    eperm: BpfProgram,
    enosys: BpfProgram,
    notify: BpfProgram,
}

impl FilterSet {
    pub(super) fn new(
        policy: &AccessPolicy,
        notify_syscalls: impl IntoIterator<Item = i64>,
    ) -> Result<Self> {
        let restricted = !policy.network_access.is_unrestricted();
        let allow_local_binding = policy.network_access.allows_local_binding();
        let unix_sockets = policy.network_access.unix_socket_access().into();
        let errno = build_errno_filter(restricted, allow_local_binding, unix_sockets)?;
        let eperm = build_io_uring_deny()?;
        let mut clone3_builder = FilterBuilder::new();
        clone3_builder.add_unconditional(libc::SYS_clone3);
        let enosys_code =
            u32::try_from(libc::ENOSYS).map_err(|_| LandstripError::IntegerTooLarge)?;
        let enosys = clone3_builder.build(SeccompAction::Errno(enosys_code))?;
        let notify = build_notify_filter(notify_syscalls)?;

        Ok(Self {
            errno,
            eperm,
            enosys,
            notify,
        })
    }

    pub(super) fn install(&self) -> Result<OwnedFd> {
        if let Some(errno) = &self.errno {
            load_program(errno, 0)?;
        }
        load_program(&self.eperm, 0)?;
        load_program(&self.enosys, 0)?;
        load_program(&self.notify, libc::SECCOMP_FILTER_FLAG_NEW_LISTENER)?.ok_or_else(|| {
            LandstripError::sandbox_setup(Mechanism::Seccomp, "listener missing").into()
        })
    }
}

fn build_errno_filter(
    needs_network: bool,
    allow_local_binding: bool,
    unix_sockets: UnixSocketFilter,
) -> Result<Option<BpfProgram>> {
    let mut builder = FilterBuilder::new();
    if needs_network {
        builder.add_socket_family_filter(libc::SYS_socket, allow_local_binding)?;
        builder.add_network_bypass_filters()?;
    }
    builder.add_unix_socket_filters(libc::SYS_socket, unix_sockets)?;
    if builder.is_empty() {
        return Ok(None);
    }
    let eafnosupport =
        u32::try_from(libc::EAFNOSUPPORT).map_err(|_| LandstripError::IntegerTooLarge)?;
    builder.build(SeccompAction::Errno(eafnosupport)).map(Some)
}

/// `io_uring` can issue network and filesystem operations without re-entering
/// brokered syscalls. Legacy timestamp syscalls also bypass Landlock and the
/// pathname broker. Deny these entry points with `EPERM` in a separate program
/// because seccompiler binds one action per filter.
fn build_io_uring_deny() -> Result<BpfProgram> {
    let mut builder = FilterBuilder::new();
    for syscall in [
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_open_tree,
        libc::SYS_mount_setattr,
    ] {
        builder.add_unconditional(syscall);
    }
    for flag in [
        libc::CLONE_NEWUSER,
        libc::CLONE_NEWNS,
        libc::CLONE_NEWPID,
        libc::CLONE_NEWNET,
        libc::CLONE_NEWCGROUP,
        libc::CLONE_NEWIPC,
        libc::CLONE_NEWUTS,
    ] {
        let flag = u64::try_from(flag).map_err(|_| LandstripError::IntegerTooLarge)?;
        builder.add_conditional_rule(
            libc::SYS_clone,
            vec![seccomp_cond(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(flag),
                flag,
            )?],
        )?;
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        builder.add_unconditional(libc::SYS_utime);
        builder.add_unconditional(libc::SYS_utimes);
        builder.add_unconditional(libc::SYS_futimesat);
    }
    let eperm = u32::try_from(libc::EPERM).map_err(|_| LandstripError::IntegerTooLarge)?;
    builder.build(SeccompAction::Errno(eperm))
}

fn build_notify_filter(syscalls: impl IntoIterator<Item = i64>) -> Result<BpfProgram> {
    let syscalls = syscalls.into_iter();
    let (lower, _) = syscalls.size_hint();
    let mut program = BpfProgram::with_capacity(lower * 2 + 7);
    let load = u16::try_from(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS)
        .map_err(|_| LandstripError::IntegerTooLarge)?;
    let jump_eq = u16::try_from(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K)
        .map_err(|_| LandstripError::IntegerTooLarge)?;
    let jump_ge = u16::try_from(libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K)
        .map_err(|_| LandstripError::IntegerTooLarge)?;
    let ret =
        u16::try_from(libc::BPF_RET | libc::BPF_K).map_err(|_| LandstripError::IntegerTooLarge)?;

    let arch = Architecture::current()?.audit;

    program.push(bpf_stmt(load, SECCOMP_DATA_ARCH_OFFSET));
    program.push(bpf_jump(jump_eq, arch, 1, 0));
    program.push(bpf_stmt(ret, libc::SECCOMP_RET_KILL_PROCESS));

    program.push(bpf_stmt(load, SECCOMP_DATA_NR_OFFSET));
    if arch == AUDIT_ARCH_X86_64 {
        // x32 shares the x86-64 audit architecture but uses a distinct ABI that
        // this broker does not decode. Reject it rather than bypassing mediation.
        program.push(bpf_jump(jump_ge, X32_SYSCALL_BIT, 0, 1));
        program.push(bpf_stmt(ret, libc::SECCOMP_RET_KILL_PROCESS));
    }
    for syscall in syscalls {
        let syscall = u32::try_from(syscall).map_err(|_| LandstripError::IntegerTooLarge)?;
        program.push(bpf_jump(jump_eq, syscall, 0, 1));
        program.push(bpf_stmt(ret, libc::SECCOMP_RET_USER_NOTIF));
    }
    program.push(bpf_stmt(ret, libc::SECCOMP_RET_ALLOW));

    Ok(program)
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

fn seccomp_cond(
    arg: u8,
    len: SeccompCmpArgLen,
    op: SeccompCmpOp,
    val: u64,
) -> Result<SeccompCondition> {
    SeccompCondition::new(arg, len, op, val)
        .map_err(|source| LandstripError::sandbox_setup(Mechanism::Seccomp, source).into())
}

fn load_program(program: &BpfProgram, flags: libc::c_ulong) -> Result<Option<OwnedFd>> {
    if program.is_empty() {
        return Err(LandstripError::sandbox_setup(Mechanism::Seccomp, "empty program").into());
    }

    // SAFETY: prctl(2) copies scalar arguments only.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(
            LandstripError::sandbox_setup(Mechanism::Seccomp, io::Error::last_os_error()).into(),
        );
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
        return Err(
            LandstripError::sandbox_setup(Mechanism::Seccomp, io::Error::last_os_error()).into(),
        );
    }

    if flags & libc::SECCOMP_FILTER_FLAG_NEW_LISTENER == 0 {
        return Ok(None);
    }

    let fd = RawFd::try_from(rc).map_err(|_| LandstripError::IntegerTooLarge)?;
    // SAFETY: seccomp returned a new listener fd when NEW_LISTENER was set.
    Ok(Some(unsafe { OwnedFd::from_raw_fd(fd) }))
}

impl FilterBuilder {
    fn add_network_bypass_filters(&mut self) -> Result<()> {
        let fastopen =
            u64::try_from(libc::MSG_FASTOPEN).map_err(|_| LandstripError::IntegerTooLarge)?;
        for (syscall, flags) in [
            (libc::SYS_sendto, 3),
            (libc::SYS_sendmsg, 2),
            (libc::SYS_sendmmsg, 3),
        ] {
            self.add_conditional_rule(
                syscall,
                vec![seccomp_cond(
                    flags,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::MaskedEq(fastopen),
                    fastopen,
                )?],
            )?;
        }

        Ok(())
    }

    pub(super) fn add_unix_socket_filters(
        &mut self,
        socket: i64,
        policy: UnixSocketFilter,
    ) -> Result<()> {
        if policy.blocks_datagrams() {
            let domain =
                u64::try_from(libc::AF_UNIX).map_err(|_| LandstripError::IntegerTooLarge)?;
            let dgram =
                u64::try_from(libc::SOCK_DGRAM).map_err(|_| LandstripError::IntegerTooLarge)?;
            self.add_conditional_rule(
                socket,
                vec![
                    seccomp_cond(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, domain)?,
                    seccomp_cond(
                        1,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK),
                        dgram,
                    )?,
                ],
            )?;
        }

        Ok(())
    }

    fn add_inet_socket_filter(&mut self, socket: i64, allow_local_binding: bool) -> Result<()> {
        let stream =
            u64::try_from(libc::SOCK_STREAM).map_err(|_| LandstripError::IntegerTooLarge)?;
        let dgram = u64::try_from(libc::SOCK_DGRAM).map_err(|_| LandstripError::IntegerTooLarge)?;
        let tcp = u64::try_from(libc::IPPROTO_TCP).map_err(|_| LandstripError::IntegerTooLarge)?;
        let udp = u64::try_from(libc::IPPROTO_UDP).map_err(|_| LandstripError::IntegerTooLarge)?;

        for domain in [libc::AF_INET, libc::AF_INET6] {
            let domain = u64::try_from(domain).map_err(|_| LandstripError::IntegerTooLarge)?;

            for ty in 0..=SOCK_TYPE_MASK {
                if ty == stream || (allow_local_binding && ty == dgram) {
                    continue;
                }

                self.add_conditional_rule(
                    socket,
                    vec![
                        seccomp_cond(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, domain)?,
                        seccomp_cond(
                            1,
                            SeccompCmpArgLen::Dword,
                            SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK),
                            ty,
                        )?,
                    ],
                )?;
            }

            for proto in 1..tcp {
                self.add_conditional_rule(
                    socket,
                    vec![
                        seccomp_cond(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, domain)?,
                        seccomp_cond(
                            1,
                            SeccompCmpArgLen::Dword,
                            SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK),
                            stream,
                        )?,
                        seccomp_cond(2, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, proto)?,
                    ],
                )?;
            }

            self.add_conditional_rule(
                socket,
                vec![
                    seccomp_cond(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, domain)?,
                    seccomp_cond(
                        1,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK),
                        stream,
                    )?,
                    seccomp_cond(2, SeccompCmpArgLen::Dword, SeccompCmpOp::Gt, tcp)?,
                ],
            )?;

            if allow_local_binding {
                for proto in 1..udp {
                    self.add_conditional_rule(
                        socket,
                        vec![
                            seccomp_cond(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, domain)?,
                            seccomp_cond(
                                1,
                                SeccompCmpArgLen::Dword,
                                SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK),
                                dgram,
                            )?,
                            seccomp_cond(2, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, proto)?,
                        ],
                    )?;
                }

                self.add_conditional_rule(
                    socket,
                    vec![
                        seccomp_cond(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, domain)?,
                        seccomp_cond(
                            1,
                            SeccompCmpArgLen::Dword,
                            SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK),
                            dgram,
                        )?,
                        seccomp_cond(2, SeccompCmpArgLen::Dword, SeccompCmpOp::Gt, udp)?,
                    ],
                )?;
            }
        }
        Ok(())
    }

    pub(super) fn add_socket_family_filter(
        &mut self,
        socket: i64,
        allow_local_binding: bool,
    ) -> Result<()> {
        self.add_inet_socket_filter(socket, allow_local_binding)?;

        for domain in [libc::AF_PACKET, libc::AF_NETLINK] {
            let domain = u64::try_from(domain).map_err(|_| LandstripError::IntegerTooLarge)?;
            self.add_conditional_rule(
                socket,
                vec![seccomp_cond(
                    0,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::Eq,
                    domain,
                )?],
            )?;
        }

        Ok(())
    }
}
