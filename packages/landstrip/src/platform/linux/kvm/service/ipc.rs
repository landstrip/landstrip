// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::super::ErrnoExt;
use super::super::fds::BrokerFd;
use super::{Arg, GuestFd, GuestMemory, GuestReg, SyscallArgs, TIMESPEC_BYTES, WORD_SIZE};
use nix::sys::stat::fstat;
use std::mem::size_of;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use syscalls::{Errno, Sysno};

// Linux UAPI `struct semid64_ds`; x86-64 has two extra padding words.
#[cfg(target_arch = "x86_64")]
const SEMID64_BYTES: usize = 104;
#[cfg(target_arch = "aarch64")]
const SEMID64_BYTES: usize = 88;
const SIGEVENT_BYTES: u64 = size_of::<libc::sigevent>() as u64;
const NOTIFY_COOKIE_LEN: usize = 32;

#[derive(Clone, Copy)]
pub(in super::super) struct MqueueNamespace(Result<libc::dev_t, Errno>);

impl MqueueNamespace {
    pub(in super::super) fn probe() -> Self {
        const NAME: &std::ffi::CStr = c"/landstrip-broker-mqueue";
        let mut attr: libc::mq_attr = unsafe { std::mem::zeroed() };
        attr.mq_maxmsg = 1;
        attr.mq_msgsize = 1;
        let raw = unsafe {
            libc::mq_open(
                NAME.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_RDONLY | libc::O_CLOEXEC,
                0o600 as libc::mode_t,
                &raw const attr,
            )
        };
        if raw < 0 {
            return Self(Err(Errno::last_os(Errno::EIO)));
        }
        let queue = unsafe { OwnedFd::from_raw_fd(raw) };
        if unsafe { libc::mq_unlink(NAME.as_ptr()) } < 0 {
            return Self(Err(Errno::last_os(Errno::EIO)));
        }
        Self(
            fstat(&queue)
                .map(|stat| stat.st_dev)
                .map_err(|errno| Errno::new(errno as i32)),
        )
    }

    pub(super) fn save(self) -> Result<libc::dev_t, i32> {
        self.0.map_err(Errno::into_raw)
    }

    pub(super) fn from_saved(device: Result<libc::dev_t, i32>) -> Self {
        Self(device.map_err(Errno::new))
    }

    fn device(self) -> Result<libc::dev_t, Errno> {
        self.0
    }

    fn pin(self, fd: GuestFd) -> Result<BrokerFd, Errno> {
        let raw = fd.valid().ok_or(Errno::EBADF)?;
        let device = self.device()?;
        let queue =
            GuestFd::duplicate_above(raw).map_err(|error| Errno::from_io(&error, Errno::EIO))?;
        let stat = fstat(&queue).map_err(|errno| Errno::new(errno as i32))?;
        if stat.st_dev != device {
            return Err(Errno::EBADF);
        }
        Ok(queue)
    }
}

impl SyscallArgs {
    pub(super) fn ipc_syscall(
        self,
        mqueue: MqueueNamespace,
        memory: &GuestMemory,
        syscall: Sysno,
    ) -> Option<u64> {
        const SEMBUF_BYTES: u64 = size_of::<libc::sembuf>() as u64;
        const MQ_ATTR_BYTES: u64 = size_of::<libc::mq_attr>() as u64;
        let specs: &[Arg<'_>] = match syscall {
            Sysno::msgget | Sysno::semget | Sysno::shmget => {
                return Some(self.forward_raw(syscall));
            }
            Sysno::msgctl => return Some(self.msgctl(memory)),
            Sysno::semctl => return Some(self.semctl(memory)),
            Sysno::shmctl => return Some(self.shmctl(memory)),
            Sysno::msgsnd | Sysno::msgrcv => &[Arg::bytes(1, self.0[2].saturating_add(WORD_SIZE))],
            Sysno::semop => &[Arg::bytes(
                1,
                u64::from(GuestReg(self.0[2]).as_u32()) * SEMBUF_BYTES,
            )],
            Sysno::semtimedop => &[
                Arg::bytes(1, u64::from(GuestReg(self.0[2]).as_u32()) * SEMBUF_BYTES),
                Arg::bytes(3, TIMESPEC_BYTES),
            ],
            Sysno::mq_open => {
                let specs = &[Arg::cstr(0), Arg::bytes(3, MQ_ATTR_BYTES)];
                return Some(super::GuestFd::guard_created(
                    self.translate_and_forward(memory, syscall, specs),
                ));
            }
            Sysno::mq_unlink => &[Arg::cstr(0)],
            Sysno::mq_notify => return Some(self.mq_notify(mqueue, memory)),
            Sysno::mq_getsetattr => {
                return Some(self.mqueue_fd_call(
                    mqueue,
                    memory,
                    syscall,
                    &[Arg::bytes(1, MQ_ATTR_BYTES), Arg::bytes(2, MQ_ATTR_BYTES)],
                ));
            }
            Sysno::mq_timedsend => {
                return Some(self.mqueue_fd_call(
                    mqueue,
                    memory,
                    syscall,
                    &[Arg::bytes(1, self.0[2]), Arg::bytes(4, TIMESPEC_BYTES)],
                ));
            }
            Sysno::mq_timedreceive => {
                return Some(self.mqueue_fd_call(
                    mqueue,
                    memory,
                    syscall,
                    &[
                        Arg::bytes(1, self.0[2]),
                        Arg::bytes(3, size_of::<libc::c_uint>() as u64),
                        Arg::bytes(4, TIMESPEC_BYTES),
                    ],
                ));
            }
            _ => return None,
        };
        Some(self.translate_and_forward(memory, syscall, specs))
    }

    fn msgctl(self, memory: &GuestMemory) -> u64 {
        const MSG_STAT_ANY: libc::c_int = 13;
        let size = match GuestReg(self.0[1]).as_i32() {
            libc::IPC_RMID => return self.forward_raw(Sysno::msgctl),
            libc::IPC_SET | libc::IPC_STAT | libc::MSG_STAT | MSG_STAT_ANY => {
                size_of::<libc::msqid_ds>()
            }
            libc::IPC_INFO | libc::MSG_INFO => size_of::<libc::msginfo>(),
            _ => return Errno::EINVAL.negated(),
        };
        self.translate_and_forward(memory, Sysno::msgctl, &[Arg::bytes(2, size as u64)])
    }

    fn semctl(self, memory: &GuestMemory) -> u64 {
        let size = match GuestReg(self.0[2]).as_i32() {
            libc::IPC_RMID
            | libc::GETPID
            | libc::GETVAL
            | libc::GETNCNT
            | libc::GETZCNT
            | libc::SETVAL => return self.forward_raw(Sysno::semctl),
            libc::IPC_SET | libc::IPC_STAT | libc::SEM_STAT | libc::SEM_STAT_ANY => SEMID64_BYTES,
            libc::IPC_INFO | libc::SEM_INFO => size_of::<[libc::c_int; 10]>(),
            libc::GETALL | libc::SETALL => return Errno::EOPNOTSUPP.negated(),
            _ => return Errno::EINVAL.negated(),
        };
        self.translate_and_forward(memory, Sysno::semctl, &[Arg::bytes(3, size as u64)])
    }

    fn shmctl(self, memory: &GuestMemory) -> u64 {
        const IPC_64: libc::c_int = 0x0100;
        const SHM_LOCK: libc::c_int = 11;
        const SHM_UNLOCK: libc::c_int = 12;
        const SHM_STAT: libc::c_int = 13;
        const SHM_INFO: libc::c_int = 14;
        const SHM_STAT_ANY: libc::c_int = 15;
        let size = match GuestReg(self.0[1]).as_i32() & !IPC_64 {
            libc::IPC_RMID | SHM_LOCK | SHM_UNLOCK => return self.forward_raw(Sysno::shmctl),
            libc::IPC_SET | libc::IPC_STAT | SHM_STAT | SHM_STAT_ANY => size_of::<libc::shmid_ds>(),
            libc::IPC_INFO => size_of::<[libc::c_ulong; 9]>(),
            SHM_INFO => size_of::<[libc::c_ulong; 6]>(),
            _ => return Errno::EINVAL.negated(),
        };
        self.translate_and_forward(memory, Sysno::shmctl, &[Arg::bytes(2, size as u64)])
    }

    fn mq_notify(mut self, mqueue: MqueueNamespace, memory: &GuestMemory) -> u64 {
        let mut cookie = [0_u8; NOTIFY_COOKIE_LEN];
        let mut event = if self.0[1] == 0 {
            None
        } else {
            let Ok(mut raw) = memory.read(self.0[1], SIGEVENT_BYTES) else {
                return Errno::EFAULT.negated();
            };
            let notify = i32::from_ne_bytes(raw[12..16].try_into().unwrap_or([0; 4]));
            if notify == libc::SIGEV_THREAD {
                let sock = i32::from_ne_bytes(raw[8..12].try_into().unwrap_or([0; 4]));
                if GuestFd::from_raw(sock).is_broker() {
                    return Errno::EBADF.negated();
                }
                let cookie_ptr = u64::from_ne_bytes(raw[0..8].try_into().unwrap_or([0; 8]));
                let Ok(bytes) = memory.read(cookie_ptr, NOTIFY_COOKIE_LEN as u64) else {
                    return Errno::EFAULT.negated();
                };
                cookie.copy_from_slice(&bytes);
                let host_cookie = cookie.as_ptr().expose_provenance() as u64;
                raw[0..8].copy_from_slice(&host_cookie.to_ne_bytes());
            }
            Some(raw)
        };
        // Check mqueue device without duplicating: closing a duplicate handle
        // flushes the process's notification registration in the kernel.
        let Some(raw) = GuestFd::from_reg(self.0[0]).valid() else {
            return Errno::EBADF.negated();
        };
        let device = match mqueue.device() {
            Ok(dev) => dev,
            Err(errno) => return errno.negated(),
        };
        if unsafe { libc::fcntl(raw, libc::F_GETFD) } < 0 {
            return Errno::EBADF.negated();
        }
        // SAFETY: `raw` was just verified open and is only inspected with `fstat`.
        let borrowed = unsafe { BorrowedFd::borrow_raw(raw) };
        let Ok(stat) = fstat(borrowed) else {
            return Errno::EBADF.negated();
        };
        if stat.st_dev != device {
            return Errno::EBADF.negated();
        }
        self.0[0] = u64::from(raw.cast_unsigned());
        self.0[1] = event
            .as_mut()
            .map_or(0, |buf| buf.as_mut_ptr().expose_provenance() as u64);
        self.forward_raw(Sysno::mq_notify)
    }

    fn mqueue_fd_call(
        self,
        mqueue: MqueueNamespace,
        memory: &GuestMemory,
        syscall: Sysno,
        specs: &[Arg<'_>],
    ) -> u64 {
        let queue = match mqueue.pin(GuestFd::from_reg(self.0[0])) {
            Ok(queue) => Some(queue),
            Err(Errno::EBADF) => None,
            Err(errno) => return errno.negated(),
        };
        // Let Linux order pointer and descriptor validation on an invalid fd.
        let mut args = self;
        args.0[0] = queue
            .as_ref()
            .map_or(u64::MAX, |fd| u64::from(fd.as_raw_fd().cast_unsigned()));
        args.translate_and_forward(memory, syscall, specs)
    }
}
