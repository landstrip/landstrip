// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! ELF payload loading and initial stack construction.
//!
//! Both static `ET_EXEC` images and dynamically linked payloads are supported.
//! A payload with a `PT_INTERP` segment gets its interpreter mapped next to it
//! and the initial stack describes both images, so the interpreter can relocate
//! the payload and map its libraries through the syscall broker.

use super::fds::GuestFd;
use super::handoff::{Inherited, SealedFile};
use super::machine::{Machine, PAGE_BYTES, RESERVED_END, STACK_TOP};
use super::memory::GuestMemory;
use anyhow::{Context, Result, bail};
use goblin::container::{Container, Ctx, Endian};
use goblin::elf::Elf;
#[cfg(target_arch = "aarch64")]
use goblin::elf::header::EM_AARCH64;
#[cfg(target_arch = "x86_64")]
use goblin::elf::header::EM_X86_64;
use goblin::elf::header::{ET_DYN, ET_EXEC};
use goblin::elf::program_header::program_header64::SIZEOF_PHDR;
use goblin::elf::program_header::{PT_INTERP, PT_LOAD, ProgramHeader};
use serde::{Deserialize, Serialize};
use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

/// `e_machine` of payloads the guest, which shares the host ABI, can run.
#[cfg(target_arch = "x86_64")]
const MACHINE: (u16, &str) = (EM_X86_64, "x86-64");
#[cfg(target_arch = "aarch64")]
const MACHINE: (u16, &str) = (EM_AARCH64, "AArch64");
const RANDOM_SIZE: usize = 16;
const SHEBANG_LIMIT: usize = 256;
const MAX_SHEBANG_DEPTH: usize = 4;

/// Guest address a position independent payload is loaded at.
const PAYLOAD_BASE: u64 = 0x0400_0000;
/// Lowest guest address a dynamic loader is loaded at, shifted upward when a
/// large `ET_EXEC` image extends past it.
const INTERPRETER_FLOOR: u64 = 0x0600_0000;
const INTERPRETER_GAP: u64 = 0x0010_0000;

const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_HWCAP: u64 = 16;
const AT_CLKTCK: u64 = 17;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
const AT_HWCAP2: u64 = 26;
const AT_EXECFN: u64 = 31;
const AT_NULL: u64 = 0;

const CLOCK_TICKS: u64 = 100;

struct Segment {
    offset: u64,
    address: u64,
    file_size: u64,
    memory_size: u64,
    prot: u32,
}

impl Segment {
    fn from_phdr(phdr: &ProgramHeader, bytes: &[u8]) -> Result<Option<Self>> {
        if phdr.p_type != PT_LOAD {
            return Ok(None);
        }
        if phdr.p_filesz > phdr.p_memsz {
            bail!("payload segment file size exceeds memory size");
        }
        if phdr.p_memsz == 0 {
            return Ok(None);
        }
        bytes
            .get(phdr.file_range())
            .context("payload has a truncated segment")?;
        let mut prot = 0u32;
        if phdr.is_read() {
            prot |= libc::PROT_READ.cast_unsigned();
        }
        if phdr.is_write() {
            prot |= libc::PROT_WRITE.cast_unsigned();
        }
        if phdr.is_executable() {
            prot |= libc::PROT_EXEC.cast_unsigned();
        }
        Ok(Some(Self {
            offset: phdr.p_offset,
            address: phdr.p_vaddr,
            file_size: phdr.p_filesz,
            memory_size: phdr.p_memsz,
            prot,
        }))
    }
}

struct Image {
    bytes: Vec<u8>,
    entry: u64,
    segments: Vec<Segment>,
    program_headers: u64,
    program_header_size: u64,
    program_header_count: u64,
    interpreter: Option<PathBuf>,
}

impl Image {
    /// Parses an ELF image, relocating a shared object to `base`.
    ///
    /// `ET_EXEC` images keep their linked addresses: their absolute references
    /// are not relocatable.
    fn parse(bytes: Vec<u8>, base: u64) -> Result<Self> {
        let header = Elf::parse_header(&bytes).context("payload is not an ELF image")?;
        let container = header.container().context("invalid ELF class")?;
        let endianness = header.endianness().context("invalid ELF endianness")?;
        if container != Container::Big || endianness != Endian::Little {
            bail!("payload is not a 64-bit little-endian ELF image");
        }
        if header.e_type != ET_EXEC && header.e_type != ET_DYN {
            bail!(
                "payload is neither an executable nor a shared object (ELF type {})",
                header.e_type
            );
        }
        let (machine, architecture) = MACHINE;
        if header.e_machine != machine {
            bail!("payload is not an {architecture} executable");
        }
        if usize::from(header.e_phentsize) != SIZEOF_PHDR {
            bail!(
                "payload has unexpected program header size {}",
                header.e_phentsize
            );
        }
        let phdrs = ProgramHeader::parse(
            &bytes,
            usize::try_from(header.e_phoff)?,
            usize::from(header.e_phnum),
            Ctx::new(container, endianness),
        )
        .context("payload has a truncated program header table")?;

        let mut segments = Vec::new();
        let mut interpreter = None;
        let mut lowest = u64::MAX;
        for phdr in &phdrs {
            if phdr.p_type == PT_INTERP && interpreter.is_none() {
                interpreter = Some(Self::parse_interpreter(phdr, &bytes)?);
                continue;
            }
            if let Some(segment) = Segment::from_phdr(phdr, &bytes)? {
                lowest = lowest.min(segment.address);
                segments.push(segment);
            }
        }
        if segments.is_empty() {
            bail!("payload has no loadable segments");
        }

        let mut image = Self {
            bytes,
            entry: header.e_entry,
            segments,
            program_headers: header.e_phoff,
            program_header_size: u64::from(header.e_phentsize),
            program_header_count: u64::from(header.e_phnum),
            interpreter,
        };
        if header.e_type == ET_DYN && base != 0 {
            let aligned = lowest - lowest % PAGE_BYTES;
            let bias = base.checked_sub(aligned).context("payload is too large")?;
            image.relocate(bias)?;
        }
        for segment in &image.segments {
            if segment.address < RESERVED_END {
                bail!("payload segment maps below the reserved address {RESERVED_END:#x}");
            }
            segment
                .address
                .checked_add(segment.memory_size)
                .context("payload segment overflows the address space")?;
        }
        Ok(image)
    }

    fn parse_interpreter(phdr: &ProgramHeader, bytes: &[u8]) -> Result<PathBuf> {
        let raw = bytes
            .get(phdr.file_range())
            .context("payload has a truncated interpreter path")?;
        let end = raw
            .iter()
            .position(|&byte| byte == 0)
            .context("interpreter path is not terminated")?;
        Ok(PathBuf::from(OsString::from_vec(raw[..end].to_vec())))
    }

    fn relocate(&mut self, bias: u64) -> Result<()> {
        let shift = |value: u64| value.checked_add(bias).context("payload is too large");
        for segment in &mut self.segments {
            segment.address = shift(segment.address)?;
        }
        self.entry = shift(self.entry)?;
        Ok(())
    }

    fn load(&self, memory: &GuestMemory) -> Result<()> {
        for segment in &self.segments {
            let start = usize::try_from(segment.offset)?;
            let end = usize::try_from(segment.offset + segment.file_size)?;
            let bytes = self
                .bytes
                .get(start..end)
                .context("payload has a truncated segment")?;
            memory.write(segment.address, bytes)?;
            if segment.memory_size > segment.file_size {
                let bss_start = segment.address + segment.file_size;
                let bss_end = segment.address + segment.memory_size;
                let page_tail = bss_start
                    .checked_next_multiple_of(PAGE_BYTES)
                    .map_or(bss_end, |aligned| aligned.min(bss_end));
                if page_tail > bss_start {
                    memory.write_zeros(bss_start, page_tail - bss_start)?;
                }
                if bss_end > page_tail {
                    let aligned_end = bss_end & !(PAGE_BYTES - 1);
                    if aligned_end > page_tail {
                        memory.discard(page_tail, aligned_end - page_tail)?;
                    }
                    if bss_end > aligned_end {
                        memory.write_zeros(aligned_end, bss_end - aligned_end)?;
                    }
                }
            }
            if segment.prot & libc::PROT_EXEC.cast_unsigned() != 0 && segment.file_size > 0 {
                memory.synchronize_instructions(segment.address, segment.file_size)?;
            }
        }
        Ok(())
    }

    fn end(&self) -> u64 {
        self.segments
            .iter()
            .map(|segment| segment.address + segment.memory_size)
            .max()
            .unwrap_or(0)
    }

    fn program_header_address(&self) -> u64 {
        self.segments
            .iter()
            .find(|segment| {
                self.program_headers >= segment.offset
                    && self.program_headers < segment.offset + segment.file_size
            })
            .map_or(0, |segment| {
                segment.address + (self.program_headers - segment.offset)
            })
    }
}

struct Shebang<'a> {
    interpreter: &'a [u8],
    argument: Option<&'a [u8]>,
}

impl<'a> Shebang<'a> {
    fn parse(bytes: &'a [u8]) -> Option<Self> {
        let line = bytes.strip_prefix(b"#!")?;
        let line = line.get(..line.len().min(SHEBANG_LIMIT))?;
        let line = match line.iter().position(|byte| *byte == b'\n') {
            Some(end) => line.get(..end)?,
            None => line,
        };
        let line = line.trim_ascii();
        let separator = line.iter().position(u8::is_ascii_whitespace);
        let (interpreter, argument) = match separator {
            Some(at) => (&line[..at], Some(line[at..].trim_ascii())),
            None => (line, None),
        };
        (!interpreter.is_empty()).then_some(Self {
            interpreter,
            argument: argument.filter(|argument| !argument.is_empty()),
        })
    }
}

/// Guest state the initial stack and the vCPU entry point are built from.
pub(crate) struct Launch {
    /// Address the vCPU starts at, which is the interpreter when there is one.
    pub(crate) start: u64,
    /// Entry point of the payload itself, reported as `AT_ENTRY`.
    entry: u64,
    header_size: u64,
    header_count: u64,
    header_address: u64,
    interpreter_base: u64,
    /// Highest mapped byte, which bounds the payload heap from below.
    pub(crate) end: u64,
    pub(crate) segments: Vec<(u64, u64, u32)>,
}

impl Launch {
    pub(crate) fn initial_stack(
        &self,
        memory: &GuestMemory,
        execfn: &OsStr,
        arguments: &[OsString],
        environment: &[OsString],
    ) -> Result<u64> {
        let mut cursor = STACK_TOP;
        let executable = Self::push_bytes(memory, cursor, execfn.as_bytes())?;
        cursor = executable;
        let mut argument_pointers = Vec::with_capacity(arguments.len());
        for argument in arguments {
            cursor = Self::push_bytes(memory, cursor, argument.as_os_str().as_bytes())?;
            argument_pointers.push(cursor);
        }
        let mut environment_pointers = Vec::with_capacity(environment.len());
        for variable in environment {
            cursor = Self::push_bytes(memory, cursor, variable.as_os_str().as_bytes())?;
            environment_pointers.push(cursor);
        }

        cursor -= u64::try_from(RANDOM_SIZE)?;
        let random = Self::random_seed()?;
        memory.write(cursor, &random)?;

        let mut words = vec![u64::try_from(argument_pointers.len())?];
        words.extend_from_slice(&argument_pointers);
        words.push(0);
        words.extend_from_slice(&environment_pointers);
        words.push(0);
        let (primary_caps, extended_caps) = Machine::hwcaps();
        let auxv = [
            (AT_PHDR, self.header_address),
            (AT_PHENT, self.header_size),
            (AT_PHNUM, self.header_count),
            (AT_PAGESZ, PAGE_BYTES),
            (AT_BASE, self.interpreter_base),
            (AT_ENTRY, self.entry),
            (AT_EXECFN, executable),
            (AT_UID, u64::from(unsafe { libc::getuid() })),
            (AT_EUID, u64::from(unsafe { libc::geteuid() })),
            (AT_GID, u64::from(unsafe { libc::getgid() })),
            (AT_EGID, u64::from(unsafe { libc::getegid() })),
            (AT_HWCAP, primary_caps),
            (AT_HWCAP2, extended_caps),
            (AT_CLKTCK, CLOCK_TICKS),
            (AT_SECURE, 0),
            (AT_RANDOM, cursor),
            (AT_NULL, 0),
        ];
        for (key, value) in auxv {
            words.push(key);
            words.push(value);
        }

        let length = u64::try_from(words.len())?
            .checked_mul(8)
            .context("stack size")?;
        cursor = (cursor - length) & !0xf;
        for (index, word) in words.iter().enumerate() {
            memory.write_u64(cursor + u64::try_from(index)? * 8, *word)?;
        }
        Ok(cursor)
    }

    fn random_seed() -> Result<[u8; RANDOM_SIZE]> {
        let mut bytes = [0u8; RANDOM_SIZE];
        getrandom::fill(&mut bytes)
            .map_err(|error| anyhow::anyhow!("generate AT_RANDOM bytes: {error}"))?;
        Ok(bytes)
    }

    fn push_bytes(memory: &GuestMemory, cursor: u64, bytes: &[u8]) -> Result<u64> {
        let length = u64::try_from(bytes.len())? + 1;
        let start = cursor
            .checked_sub(length)
            .context("initial stack underflow")?;
        memory.write(start, bytes)?;
        memory.write(start + length - 1, &[0])?;
        Ok(start)
    }

    pub(crate) fn inherited_environment() -> Vec<OsString> {
        std::env::vars_os()
            .map(|(key, value)| Self::join_env(&key, &value))
            .collect()
    }

    fn join_env(key: &OsStr, value: &OsStr) -> OsString {
        let mut entry = OsString::from(key);
        entry.push("=");
        entry.push(value);
        entry
    }
}

pub(crate) struct Payload {
    image: Image,
    interpreter: Option<Image>,
}

impl Payload {
    /// Maps the payload and its interpreter, describing the resulting address
    /// space to the rest of the backend.
    pub(crate) fn load(&self, memory: &GuestMemory) -> Result<Launch> {
        self.image.load(memory)?;
        if let Some(interpreter) = &self.interpreter {
            interpreter.load(memory)?;
        }
        let mut segments = Vec::new();
        for seg in self.image.segments.iter().chain(
            self.interpreter
                .iter()
                .flat_map(|interpreter| interpreter.segments.iter()),
        ) {
            let start = seg.address & !(PAGE_BYTES - 1);
            let end = (seg.address + seg.memory_size)
                .checked_add(PAGE_BYTES - 1)
                .map_or(u64::MAX, |aligned| aligned & !(PAGE_BYTES - 1));
            segments.push((start, end, seg.prot));
        }
        Ok(Launch {
            start: self
                .interpreter
                .as_ref()
                .map_or(self.image.entry, |interpreter| interpreter.entry),
            entry: self.image.entry,
            header_size: self.image.program_header_size,
            header_count: self.image.program_header_count,
            header_address: self.image.program_header_address(),
            interpreter_base: self.interpreter.as_ref().map_or(0, |image| {
                image.segments.first().map_or(0, |segment| segment.address)
            }),
            end: self
                .interpreter
                .as_ref()
                .map_or(self.image.end(), |interpreter| {
                    interpreter.end().max(self.image.end())
                }),
            segments,
        })
    }
}

pub(crate) enum LoadError {
    Denied(syscalls::Errno),
    Io(io::Error),
    InvalidElf(anyhow::Error),
}

pub(crate) struct LoadedProgram {
    pub(crate) payload: Payload,
    pub(crate) arguments: Vec<OsString>,
    pub(crate) executable: PathBuf,
    pub(crate) comm: CString,
}

/// Holds sealed descriptors for the already authorized ELF bytes. Neither
/// pathname is reopened after discarding the old broker image.
#[derive(Deserialize, Serialize)]
pub(super) struct ExecProgram {
    image: RawFd,
    interpreter: Option<RawFd>,
    arguments: Vec<OsString>,
    executable: OsString,
    comm: CString,
}

impl ExecProgram {
    pub(super) fn save(program: LoadedProgram, inherit: &mut Inherited) -> Result<Self> {
        Ok(Self {
            image: inherit.save_image(&program.payload.image.bytes)?,
            interpreter: program
                .payload
                .interpreter
                .as_ref()
                .map(|image| inherit.save_image(&image.bytes))
                .transpose()?,
            arguments: program.arguments,
            executable: program.executable.into_os_string(),
            comm: program.comm,
        })
    }

    pub(super) fn restore(self, floor: RawFd) -> Result<LoadedProgram> {
        let image = Image::parse(SealedFile::load_bytes(self.image, floor)?, PAYLOAD_BASE)?;
        let interpreter_base = (image.end().div_ceil(PAGE_BYTES) * PAGE_BYTES + INTERPRETER_GAP)
            .max(INTERPRETER_FLOOR);
        let interpreter = self
            .interpreter
            .map(|fd| Image::parse(SealedFile::load_bytes(fd, floor)?, interpreter_base))
            .transpose()?;
        Ok(LoadedProgram {
            payload: Payload { image, interpreter },
            arguments: self.arguments,
            executable: self.executable.into(),
            comm: self.comm,
        })
    }
}

enum LoadSource<'a> {
    Path { dirfd: RawFd, path: &'a Path },
    Descriptor(std::os::fd::BorrowedFd<'a>),
}

pub(crate) struct LoadRequest<'a> {
    source: LoadSource<'a>,
    cwd_dirfd: RawFd,
    invoked: &'a OsStr,
    arguments: &'a [OsString],
    follow: bool,
    relocate_fds: bool,
    path_inaccessible: bool,
}

impl<'a> LoadRequest<'a> {
    pub(crate) fn initial(cwd_dirfd: RawFd, path: &'a Path, arguments: &'a [OsString]) -> Self {
        Self {
            source: LoadSource::Path {
                dirfd: libc::AT_FDCWD,
                path,
            },
            cwd_dirfd,
            invoked: path.as_os_str(),
            arguments,
            follow: true,
            relocate_fds: false,
            path_inaccessible: false,
        }
    }

    pub(crate) const fn guest_path(
        dirfd: RawFd,
        path: &'a Path,
        invoked: &'a OsStr,
        arguments: &'a [OsString],
    ) -> Self {
        Self {
            source: LoadSource::Path { dirfd, path },
            cwd_dirfd: libc::AT_FDCWD,
            invoked,
            arguments,
            follow: true,
            relocate_fds: true,
            path_inaccessible: false,
        }
    }

    pub(crate) const fn guest_fd(
        fd: std::os::fd::BorrowedFd<'a>,
        invoked: &'a OsStr,
        arguments: &'a [OsString],
    ) -> Self {
        Self {
            source: LoadSource::Descriptor(fd),
            cwd_dirfd: libc::AT_FDCWD,
            invoked,
            arguments,
            follow: true,
            relocate_fds: true,
            path_inaccessible: false,
        }
    }

    pub(crate) const fn follow_symlinks(mut self, follow: bool) -> Self {
        self.follow = follow;
        self
    }

    pub(crate) const fn mark_inaccessible(mut self, inaccessible: bool) -> Self {
        self.path_inaccessible = inaccessible;
        self
    }

    pub(crate) fn load(
        self,
        mut authorize: impl FnMut(&Path) -> Option<syscalls::Errno>,
    ) -> std::result::Result<LoadedProgram, LoadError> {
        let (mut bytes, mut canonical, mut comm) = match self.source {
            LoadSource::Path { dirfd, path } => {
                Executable::open_path(dirfd, path, self.follow, self.relocate_fds)
                    .map_err(LoadError::Io)?
            }
            LoadSource::Descriptor(fd) => Executable::read_fd(fd, false).map_err(LoadError::Io)?,
        };
        let mut argv = self.arguments.to_vec();
        let mut script_name = self.invoked.to_os_string();
        for depth in 0..=MAX_SHEBANG_DEPTH {
            let Some(shebang) = Shebang::parse(&bytes) else {
                break;
            };
            if depth == MAX_SHEBANG_DEPTH {
                return Err(LoadError::Io(io::Error::from_raw_os_error(libc::ELOOP)));
            }
            if depth == 0 && self.path_inaccessible {
                return Err(LoadError::Io(io::Error::from_raw_os_error(libc::ENOENT)));
            }
            let interpreter = PathBuf::from(OsString::from_vec(shebang.interpreter.to_vec()));
            let mut next_argv = vec![interpreter.as_os_str().to_os_string()];
            if let Some(argument) = shebang.argument {
                next_argv.push(OsString::from_vec(argument.to_vec()));
            }
            next_argv.push(script_name);
            if let Some(rest) = argv.get(1..) {
                next_argv.extend_from_slice(rest);
            }
            if let Some(errno) = authorize(&interpreter) {
                return Err(LoadError::Denied(errno));
            }
            let base_fd = if interpreter.is_absolute() {
                libc::AT_FDCWD
            } else {
                self.cwd_dirfd
            };
            let (next_bytes, next_canonical, next_comm) =
                Executable::open_path(base_fd, &interpreter, true, self.relocate_fds)
                    .map_err(LoadError::Io)?;
            bytes = next_bytes;
            canonical = next_canonical;
            comm = next_comm;
            script_name = interpreter.into_os_string();
            argv = next_argv;
        }
        let image = Image::parse(bytes, PAYLOAD_BASE).map_err(LoadError::InvalidElf)?;
        let interpreter_base = (image.end().div_ceil(PAGE_BYTES) * PAGE_BYTES + INTERPRETER_GAP)
            .max(INTERPRETER_FLOOR);
        let interpreter = match image.interpreter.clone() {
            Some(interp_path) => {
                if let Some(errno) = authorize(&interp_path) {
                    return Err(LoadError::Denied(errno));
                }
                let base_fd = if interp_path.is_absolute() {
                    libc::AT_FDCWD
                } else {
                    self.cwd_dirfd
                };
                let (interp_bytes, _, _) =
                    Executable::open_path(base_fd, &interp_path, true, self.relocate_fds)
                        .map_err(LoadError::Io)?;
                Some(Image::parse(interp_bytes, interpreter_base).map_err(LoadError::InvalidElf)?)
            }
            None => None,
        };
        if matches!(self.source, LoadSource::Path { .. }) {
            comm = Executable::name(Path::new(self.invoked)).map_err(LoadError::Io)?;
        }
        Ok(LoadedProgram {
            payload: Payload { image, interpreter },
            arguments: argv,
            executable: canonical,
            comm,
        })
    }
}

struct Executable;

impl Executable {
    fn open_path(
        dirfd: RawFd,
        path: &Path,
        follow: bool,
        relocate: bool,
    ) -> io::Result<(Vec<u8>, PathBuf, CString)> {
        let cpath = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        let mut flags = libc::O_PATH | libc::O_CLOEXEC;
        if !follow {
            flags |= libc::O_NOFOLLOW;
        }
        let raw = unsafe { libc::openat(dirfd, cpath.as_ptr(), flags) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        if relocate {
            let fd = GuestFd::relocate_above(owned)?;
            Self::read_fd(std::os::fd::AsFd::as_fd(&fd), !follow)
        } else {
            Self::read_fd(std::os::fd::AsFd::as_fd(&owned), !follow)
        }
    }

    fn read_fd(
        fd: std::os::fd::BorrowedFd<'_>,
        reject_symlink_loop: bool,
    ) -> io::Result<(Vec<u8>, PathBuf, CString)> {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let stat = unsafe { stat.assume_init() };
        if reject_symlink_loop && (stat.st_mode & libc::S_IFMT) == libc::S_IFLNK {
            return Err(io::Error::from_raw_os_error(libc::ELOOP));
        }
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG || (stat.st_mode & 0o111) == 0 {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        if let Err(errno) = unsafe {
            syscalls::syscall!(
                syscalls::Sysno::faccessat2,
                fd.as_raw_fd().cast_unsigned() as usize,
                c"".as_ptr().expose_provenance(),
                libc::X_OK.cast_unsigned() as usize,
                libc::AT_EMPTY_PATH.cast_unsigned() as usize
            )
        } && errno != syscalls::Errno::ENOSYS
        {
            return Err(io::Error::from_raw_os_error(errno.into_raw()));
        }
        let proc_fd = format!("/proc/self/fd/{}", fd.as_raw_fd());
        let canonical = std::fs::read_link(&proc_fd).unwrap_or_default();
        let target = canonical.as_os_str().as_bytes();
        let name = if target.ends_with(b" (deleted)") {
            use std::os::unix::fs::MetadataExt;
            let linked = std::fs::metadata(&canonical).is_ok_and(|metadata| {
                metadata.dev() == stat.st_dev && metadata.ino() == stat.st_ino
            });
            if linked {
                target
            } else {
                target.strip_suffix(b" (deleted)").unwrap_or(target)
            }
        } else {
            target
        };
        let comm = Self::name(Path::new(OsStr::from_bytes(name)))?;
        let bytes = std::fs::read(&proc_fd)?;
        Ok((bytes, canonical, comm))
    }

    fn name(path: &Path) -> io::Result<CString> {
        CString::new(path.file_name().unwrap_or(path.as_os_str()).as_bytes())
            .map_err(io::Error::other)
    }
}
