// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::error::{Error as LandstripError, Mechanism};
use crate::policy::AccessPolicy;
use anyhow::Result;
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};
use std::collections::BTreeMap;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::ptr;
use syscalls::Sysno;

const SOCK_TYPE_MASK: u64 = 0x0f;
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const SECCOMP_DATA_ARGS_OFFSET: u32 = 16;
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
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
            arch => Err(LandstripError::sandbox_setup(
                Mechanism::Seccomp,
                format!("unsupported target arch: {arch}"),
            )
            .into()),
        }
    }
}

pub(super) type RuleMap = BTreeMap<i64, Vec<SeccompRule>>;

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

    fn cond(
        arg: u8,
        len: SeccompCmpArgLen,
        op: SeccompCmpOp,
        val: u64,
    ) -> Result<SeccompCondition> {
        SeccompCondition::new(arg, len, op, val)
            .map_err(|source| LandstripError::sandbox_setup(Mechanism::Seccomp, source).into())
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
                        Self::cond(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, domain)?,
                        Self::cond(
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
                        Self::cond(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, domain)?,
                        Self::cond(
                            1,
                            SeccompCmpArgLen::Dword,
                            SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK),
                            stream,
                        )?,
                        Self::cond(2, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, proto)?,
                    ],
                )?;
            }

            self.add_conditional_rule(
                socket,
                vec![
                    Self::cond(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, domain)?,
                    Self::cond(
                        1,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK),
                        stream,
                    )?,
                    Self::cond(2, SeccompCmpArgLen::Dword, SeccompCmpOp::Gt, tcp)?,
                ],
            )?;

            if allow_local_binding {
                for proto in 1..udp {
                    self.add_conditional_rule(
                        socket,
                        vec![
                            Self::cond(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, domain)?,
                            Self::cond(
                                1,
                                SeccompCmpArgLen::Dword,
                                SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK),
                                dgram,
                            )?,
                            Self::cond(2, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, proto)?,
                        ],
                    )?;
                }

                self.add_conditional_rule(
                    socket,
                    vec![
                        Self::cond(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, domain)?,
                        Self::cond(
                            1,
                            SeccompCmpArgLen::Dword,
                            SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK),
                            dgram,
                        )?,
                        Self::cond(2, SeccompCmpArgLen::Dword, SeccompCmpOp::Gt, udp)?,
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
                vec![Self::cond(
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

pub(super) struct FilterSet {
    errno: Option<BpfProgram>,
    enosys: BpfProgram,
    notify: BpfProgram,
    eperm: BpfProgram,
}

impl FilterSet {
    const EPERM_SYSCALLS: &[Sysno] = &[
        Sysno::io_uring_setup,
        Sysno::io_uring_enter,
        Sysno::io_uring_register,
        Sysno::io_setup,
        Sysno::io_destroy,
        Sysno::io_submit,
        Sysno::io_cancel,
        Sysno::io_getevents,
        Sysno::io_pgetevents,
        Sysno::unshare,
        Sysno::setns,
        Sysno::mount,
        Sysno::umount2,
        Sysno::pivot_root,
        Sysno::chroot,
        Sysno::move_mount,
        Sysno::fsopen,
        Sysno::fsconfig,
        Sysno::fsmount,
        Sysno::fspick,
        Sysno::open_tree,
        Sysno::open_tree_attr,
        Sysno::mount_setattr,
        Sysno::statmount,
        Sysno::listmount,
        Sysno::name_to_handle_at,
        Sysno::open_by_handle_at,
        Sysno::fanotify_init,
        Sysno::fanotify_mark,
        Sysno::quotactl,
        Sysno::quotactl_fd,
        Sysno::acct,
        Sysno::swapon,
        Sysno::swapoff,
        Sysno::sethostname,
        Sysno::setdomainname,
        Sysno::syslog,
        Sysno::init_module,
        Sysno::finit_module,
        Sysno::delete_module,
        Sysno::kexec_load,
        Sysno::kexec_file_load,
        #[cfg(target_arch = "x86_64")]
        Sysno::ioperm,
        #[cfg(target_arch = "x86_64")]
        Sysno::iopl,
        Sysno::bpf,
        Sysno::perf_event_open,
        Sysno::userfaultfd,
        Sysno::seccomp,
        Sysno::landlock_create_ruleset,
        Sysno::landlock_add_rule,
        Sysno::landlock_restrict_self,
        Sysno::pidfd_getfd,
        Sysno::process_vm_readv,
        Sysno::process_vm_writev,
        Sysno::process_madvise,
        Sysno::process_mrelease,
        Sysno::add_key,
        Sysno::request_key,
        Sysno::keyctl,
        Sysno::lsm_get_self_attr,
        Sysno::lsm_set_self_attr,
        Sysno::lsm_list_modules,
    ];

    pub(super) fn new(
        policy: &AccessPolicy,
        notify_syscalls: impl IntoIterator<Item = i64>,
    ) -> Result<Self> {
        let restricted = !policy.network_access.is_unrestricted();
        let allow_local_binding = policy.network_access.allows_local_binding();
        let errno = Self::build_errno_filter(restricted, allow_local_binding)?;
        let mut clone3_builder = FilterBuilder::new();
        clone3_builder.add_unconditional(libc::SYS_clone3);
        let enosys_code =
            u32::try_from(libc::ENOSYS).map_err(|_| LandstripError::IntegerTooLarge)?;
        let enosys = clone3_builder.build(SeccompAction::Errno(enosys_code))?;
        let notify = Self::build_notify_filter(notify_syscalls)?;
        let eperm = Self::build_eperm_filter()?;

        Ok(Self {
            errno,
            enosys,
            notify,
            eperm,
        })
    }

    pub(super) fn install(&self) -> Result<OwnedFd> {
        if let Some(errno) = &self.errno {
            Self::load_program(errno, 0)?;
        }
        Self::load_program(&self.enosys, 0)?;
        let listener = Self::load_program(&self.notify, libc::SECCOMP_FILTER_FLAG_NEW_LISTENER)?
            .ok_or_else(|| LandstripError::sandbox_setup(Mechanism::Seccomp, "listener missing"))?;
        Self::load_program(&self.eperm, 0)?;
        Ok(listener)
    }

    fn build_errno_filter(
        needs_network: bool,
        allow_local_binding: bool,
    ) -> Result<Option<BpfProgram>> {
        let mut builder = FilterBuilder::new();
        if needs_network {
            builder.add_socket_family_filter(libc::SYS_socket, allow_local_binding)?;
        }
        if builder.is_empty() {
            return Ok(None);
        }
        let eafnosupport =
            u32::try_from(libc::EAFNOSUPPORT).map_err(|_| LandstripError::IntegerTooLarge)?;
        builder.build(SeccompAction::Errno(eafnosupport)).map(Some)
    }

    fn build_eperm_filter() -> Result<BpfProgram> {
        let mut builder = FilterBuilder::new();
        for &syscall in Self::EPERM_SYSCALLS {
            builder.add_unconditional(i64::from(syscall.id()));
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
                vec![FilterBuilder::cond(
                    0,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::MaskedEq(flag),
                    flag,
                )?],
            )?;
        }
        #[cfg(target_arch = "x86_64")]
        {
            builder.add_unconditional(libc::SYS_utime);
            builder.add_unconditional(libc::SYS_utimes);
            builder.add_unconditional(libc::SYS_futimesat);
        }
        let eperm = u32::try_from(libc::EPERM).map_err(|_| LandstripError::IntegerTooLarge)?;
        builder.build(SeccompAction::Errno(eperm))
    }

    fn build_notify_filter(syscalls: impl IntoIterator<Item = i64>) -> Result<BpfProgram> {
        let syscalls: Vec<i64> = syscalls.into_iter().collect();
        let mut program = BpfProgram::with_capacity(syscalls.len() * 2 + 16);
        let load = u16::try_from(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS)
            .map_err(|_| LandstripError::IntegerTooLarge)?;
        let jump_eq = u16::try_from(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K)
            .map_err(|_| LandstripError::IntegerTooLarge)?;
        let jump_ge = u16::try_from(libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K)
            .map_err(|_| LandstripError::IntegerTooLarge)?;
        let jump_set = u16::try_from(libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K)
            .map_err(|_| LandstripError::IntegerTooLarge)?;
        let ret = u16::try_from(libc::BPF_RET | libc::BPF_K)
            .map_err(|_| LandstripError::IntegerTooLarge)?;

        let arch = Architecture::current()?.audit;

        program.push(Self::bpf_stmt(load, SECCOMP_DATA_ARCH_OFFSET));
        program.push(Self::bpf_jump(jump_eq, arch, 1, 0));
        program.push(Self::bpf_stmt(ret, libc::SECCOMP_RET_KILL_PROCESS));

        program.push(Self::bpf_stmt(load, SECCOMP_DATA_NR_OFFSET));
        if arch == AUDIT_ARCH_X86_64 {
            program.push(Self::bpf_jump(jump_ge, X32_SYSCALL_BIT, 0, 1));
            program.push(Self::bpf_stmt(ret, libc::SECCOMP_RET_KILL_PROCESS));
        }
        let sendto_nr =
            u32::try_from(libc::SYS_sendto).map_err(|_| LandstripError::IntegerTooLarge)?;
        let fastopen =
            u32::try_from(libc::MSG_FASTOPEN).map_err(|_| LandstripError::IntegerTooLarge)?;
        for syscall in syscalls {
            let syscall = u32::try_from(syscall).map_err(|_| LandstripError::IntegerTooLarge)?;
            if syscall == sendto_nr {
                program.push(Self::bpf_jump(jump_eq, sendto_nr, 0, 8));
                program.push(Self::bpf_stmt(load, SECCOMP_DATA_ARGS_OFFSET + 4 * 8));
                program.push(Self::bpf_jump(jump_eq, 0, 0, 4));
                program.push(Self::bpf_stmt(load, SECCOMP_DATA_ARGS_OFFSET + 4 * 8 + 4));
                program.push(Self::bpf_jump(jump_eq, 0, 0, 2));
                program.push(Self::bpf_stmt(load, SECCOMP_DATA_ARGS_OFFSET + 3 * 8));
                program.push(Self::bpf_jump(jump_set, fastopen, 0, 1));
                program.push(Self::bpf_stmt(ret, libc::SECCOMP_RET_USER_NOTIF));
                program.push(Self::bpf_stmt(ret, libc::SECCOMP_RET_ALLOW));
                continue;
            }
            program.push(Self::bpf_jump(jump_eq, syscall, 0, 1));
            program.push(Self::bpf_stmt(ret, libc::SECCOMP_RET_USER_NOTIF));
        }
        program.push(Self::bpf_stmt(ret, libc::SECCOMP_RET_ALLOW));

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

    fn load_program(program: &BpfProgram, flags: libc::c_ulong) -> Result<Option<OwnedFd>> {
        if program.is_empty() {
            return Err(LandstripError::sandbox_setup(Mechanism::Seccomp, "empty program").into());
        }

        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(LandstripError::sandbox_setup(
                Mechanism::Seccomp,
                io::Error::last_os_error(),
            )
            .into());
        }

        let len =
            libc::c_ushort::try_from(program.len()).map_err(|_| LandstripError::IntegerTooLarge)?;
        let filter = SockFilterProg {
            len,
            filter: program.as_ptr(),
        };

        let rc = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                flags,
                ptr::addr_of!(filter),
            )
        };
        if rc < 0 {
            return Err(LandstripError::sandbox_setup(
                Mechanism::Seccomp,
                io::Error::last_os_error(),
            )
            .into());
        }

        if flags & libc::SECCOMP_FILTER_FLAG_NEW_LISTENER == 0 {
            return Ok(None);
        }

        let fd = RawFd::try_from(rc).map_err(|_| LandstripError::IntegerTooLarge)?;
        Ok(Some(unsafe { OwnedFd::from_raw_fd(fd) }))
    }
}
