// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Descriptor and state transfer across a native broker exec.

use super::fds::{BrokerFd, BrokerHandle, GuestFd};
use anyhow::{Context, Result, ensure};
use goblin::elf::dynamic::{DT_RPATH, DT_RUNPATH, dyn64};
use goblin::elf::header::{EI_CLASS, EI_DATA, ELFCLASS64, ELFDATA2LSB, ELFMAG, SELFMAG, header64};
use goblin::elf::program_header::program_header64::{ProgramHeader, SIZEOF_PHDR};
use nix::fcntl::{OFlag, open};
use nix::sys::memfd::{MFdFlags, memfd_create};
use nix::sys::stat::Mode;
use serde::{Serialize, de::DeserializeOwned};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileExt;
use std::sync::OnceLock;

pub(super) const RESUME: &str = "--kvm-resume";
const SEALS: libc::c_int =
    libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;

pub(super) struct RestartImage(BrokerFd);

impl RestartImage {
    pub(super) fn can_restart_self() -> bool {
        static SAFE: OnceLock<bool> = OnceLock::new();
        if cfg!(target_feature = "crt-static") {
            return true;
        }
        *SAFE.get_or_init(|| {
            let Ok(mut exe) = File::open("/proc/self/exe") else {
                return false;
            };
            let Ok(header) = header64::Header::from_fd(&mut exe) else {
                return false;
            };
            if &header.e_ident[..SELFMAG] != ELFMAG
                || header.e_ident[EI_CLASS] != ELFCLASS64
                || header.e_ident[EI_DATA] != ELFDATA2LSB
                || usize::from(header.e_phentsize) != SIZEOF_PHDR
                || header.e_phnum > 256
            {
                return false;
            }
            let mut phdr_bytes = vec![0_u8; usize::from(header.e_phnum) * SIZEOF_PHDR];
            if exe.read_exact_at(&mut phdr_bytes, header.e_phoff).is_err() {
                return false;
            }
            let phdrs = ProgramHeader::from_bytes(&phdr_bytes, usize::from(header.e_phnum));
            let Ok(dynamic) = dyn64::from_fd(&exe, &phdrs) else {
                return false;
            };
            dynamic.is_none_or(|entries| {
                entries
                    .iter()
                    .all(|entry| !matches!(entry.d_tag, DT_RPATH | DT_RUNPATH))
            })
        })
    }

    pub(super) fn pin() -> Result<Option<Self>> {
        if !Self::can_restart_self() {
            return Ok(None);
        }
        let fd = open(
            "/proc/self/exe",
            OFlag::O_PATH | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .context("pin broker executable")?;
        Ok(Some(Self(GuestFd::relocate_above(fd)?)))
    }

    pub(super) fn from_handoff(raw: RawFd, floor: RawFd) -> Result<Self> {
        Inherited::adopt(raw, floor).map(Self)
    }

    pub(super) fn keep(&self, inherit: &mut Inherited) -> Result<RawFd> {
        inherit.keep(self.0.as_fd())
    }

    pub(super) fn exec(&self, capsule: RawFd) -> Result<std::convert::Infallible> {
        let number = CString::new(capsule.to_string())?;
        let argv = [
            c"landstrip".as_ptr(),
            c"--kvm-resume".as_ptr(),
            number.as_ptr(),
            std::ptr::null(),
        ];
        let envp = [std::ptr::null::<libc::c_char>()];
        let err = unsafe {
            syscalls::syscall!(
                syscalls::Sysno::execveat,
                self.0.as_raw_fd().cast_unsigned() as usize,
                c"".as_ptr().expose_provenance(),
                argv.as_ptr().expose_provenance(),
                envp.as_ptr().expose_provenance(),
                libc::AT_EMPTY_PATH.cast_unsigned() as usize
            )
        }
        .err()
        .map_or_else(io::Error::last_os_error, |errno| {
            io::Error::from_raw_os_error(errno.into_raw())
        });
        Err(err).context("re-execute the KVM broker")
    }
}

/// Holds copies that survive exec without changing close-on-exec on the
/// running broker's own descriptors. An unsuccessful exec closes the copies.
#[derive(Default)]
pub(super) struct Inherited(Vec<BrokerFd>);

impl Inherited {
    pub(super) fn keep(&mut self, fd: BorrowedFd<'_>) -> Result<RawFd> {
        let copy =
            GuestFd::duplicate_above(fd.as_raw_fd()).context("duplicate broker descriptor")?;
        Self::set_fd_flags(copy.as_fd(), 0)?;
        let raw = copy.as_raw_fd();
        self.0.push(copy);
        Ok(raw)
    }

    pub(super) fn save(&mut self, state: &impl Serialize) -> Result<RawFd> {
        self.save_sealed("landstrip-resume", |file| {
            let mut writer = BufWriter::new(file);
            serde_json::to_writer(&mut writer, state).context("encode broker handoff capsule")?;
            writer.flush().context("write broker handoff capsule")
        })
    }

    pub(super) fn save_image(&mut self, bytes: &[u8]) -> Result<RawFd> {
        self.save_sealed("landstrip-elf", |file| {
            file.write_all(bytes).context("write handoff ELF image")
        })
    }

    fn save_sealed(
        &mut self,
        name: &str,
        write: impl FnOnce(&mut File) -> Result<()>,
    ) -> Result<RawFd> {
        let _fd_lock = GuestFd::read_fd_table();
        let fd = memfd_create(name, MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING)
            .context("create broker handoff file")?;
        let mut file = File::from(fd);
        write(&mut file)?;
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, SEALS) } < 0 {
            return Err(io::Error::last_os_error()).context("seal broker handoff file");
        }
        self.keep(file.as_fd())
    }

    pub(super) fn adopt(raw: RawFd, floor: RawFd) -> Result<BrokerFd> {
        ensure!(
            raw >= floor && floor >= 3,
            "invalid broker handoff descriptor: {raw}"
        );
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
        ensure!(
            flags == 0,
            "broker handoff descriptor is not inherited: {raw}"
        );
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        Self::set_fd_flags(fd.as_fd(), libc::FD_CLOEXEC)?;
        Ok(BrokerFd::register(fd))
    }

    fn set_fd_flags(fd: BorrowedFd<'_>, flags: libc::c_int) -> Result<()> {
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags) } < 0 {
            return Err(io::Error::last_os_error()).context("set handoff descriptor flags");
        }
        Ok(())
    }
}

pub(super) struct SealedFile(BrokerHandle<File>);

impl SealedFile {
    pub(super) fn open(fd: BrokerFd) -> Result<Self> {
        let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
        ensure!(
            seals >= 0 && seals & SEALS == SEALS,
            "broker handoff file is not sealed"
        );
        let mut file = fd.map_same_fd(File::from);
        file.get_mut()
            .rewind()
            .context("rewind broker handoff file")?;
        Ok(Self(file))
    }

    pub(super) fn load_json<T: DeserializeOwned>(fd: BrokerFd) -> Result<T> {
        serde_json::from_reader(BufReader::new(Self::open(fd)?))
            .context("decode broker handoff capsule")
    }

    pub(super) fn load_bytes(raw: RawFd, floor: RawFd) -> Result<Vec<u8>> {
        let mut file = Self::open(Inherited::adopt(raw, floor)?)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .context("read handoff ELF image")?;
        Ok(bytes)
    }
}

impl Read for SealedFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.get_mut().read(buf)
    }
}
