// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Guest physical memory backed by a private anonymous host mapping.
//!
//! Guest physical addresses are offsets into this mapping, so the host address
//! of a guest buffer is the mapping base plus the guest address.

use super::ErrnoExt;
use anyhow::{Context, Result, bail};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::io;
use std::ops::Range;
use std::os::fd::RawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use syscalls::Errno;
use vm_memory::mmap::MmapRegion;

const PATH_MAX_BYTES: usize = 4096;

/// The outcome of [`GuestMemory::compare_exchange_u32`].
pub(crate) struct Exchange {
    /// The word before the exchange, which happened if it was the expected one.
    pub(crate) found: u32,
    /// Whether a concurrent update between reading and writing was excluded.
    pub(crate) atomic: bool,
}

pub(crate) struct HostCString(Option<CString>);

impl HostCString {
    pub(crate) fn read(memory: &GuestMemory, offset: u64) -> std::result::Result<Self, Errno> {
        if offset == 0 {
            return Ok(Self(None));
        }
        let mut bytes = memory.read_cstring(offset, PATH_MAX_BYTES)?;
        bytes.push(0);
        Ok(Self(CString::from_vec_with_nul(bytes).ok()))
    }

    pub(crate) fn is_null(&self) -> bool {
        self.0.is_none()
    }

    pub(crate) fn is_empty_non_null(&self) -> bool {
        self.0
            .as_deref()
            .is_some_and(|value| value.to_bytes().is_empty())
    }

    pub(crate) fn as_bytes(&self) -> Option<&[u8]> {
        self.0.as_deref().map(CStr::to_bytes)
    }

    pub(crate) fn as_path(&self) -> &Path {
        match &self.0 {
            Some(cstr) => Path::new(OsStr::from_bytes(cstr.to_bytes())),
            None => Path::new(""),
        }
    }

    pub(crate) fn host_ptr(&self) -> u64 {
        match &self.0 {
            Some(cstr) => cstr.as_ptr().expose_provenance() as u64,
            None => 0,
        }
    }

    pub(crate) fn into_inner(self) -> Option<CString> {
        self.0
    }
}

#[derive(Debug)]
pub(crate) struct GuestMemory {
    pointer: *mut u8,
    size: usize,
    owned: AtomicBool,
    custom_mappings: AtomicBool,
}

// SAFETY: `pointer..pointer + size` is a live anonymous host mapping for the
// lifetime of `GuestMemory`, and all accesses copy through raw pointers or
// atomics without creating Rust references that alias concurrent guest writes.
unsafe impl Send for GuestMemory {}
// SAFETY: see `Send` above.
unsafe impl Sync for GuestMemory {}

impl GuestMemory {
    pub(crate) fn new(size: usize) -> Result<Self> {
        // `MmapRegion::new` maps anonymously with PROT_READ | PROT_WRITE and
        // MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE.
        let region = MmapRegion::<()>::new(size).context("map guest memory")?;
        let pointer = region.as_ptr();
        // Ownership of the mapping moves to `Drop`, which munmaps it unless
        // `disown` passed it to a forked child.
        std::mem::forget(region);
        Ok(Self {
            pointer,
            size,
            owned: AtomicBool::new(true),
            custom_mappings: AtomicBool::new(false),
        })
    }

    /// Wraps the mapping this process inherited from its parent.
    ///
    /// The child of a `fork` owns a copy-on-write view of the same guest
    /// memory, so it addresses the same guest physical memory and unmaps only
    /// its own view.
    pub(crate) fn shared(&self) -> Self {
        Self {
            pointer: self.pointer,
            size: self.size,
            owned: AtomicBool::new(true),
            custom_mappings: AtomicBool::new(self.custom_mappings.load(Ordering::Acquire)),
        }
    }

    /// Releases ownership of the mapping without unmapping it.
    pub(crate) fn disown(&self) {
        self.owned.store(false, Ordering::Relaxed);
    }

    /// Clears the payload address space, which an `execve` replaces.
    pub(crate) fn reset(&self, start: u64) -> Result<()> {
        if self.custom_mappings.swap(false, Ordering::AcqRel) {
            return self.restore_anonymous(start, self.size() - start);
        }
        self.discard(start, self.size() - start)
    }

    /// Replaces `offset..offset + length` with zero-fill-on-demand pages
    /// without faulting untouched reservations into host physical memory.
    pub(crate) fn discard(&self, offset: u64, length: u64) -> Result<()> {
        let range = self.range(offset, length)?;
        if offset.is_multiple_of(super::machine::PAGE_BYTES)
            && length.is_multiple_of(super::machine::PAGE_BYTES)
        {
            // SAFETY: `range` is page-aligned inside the private anonymous
            // mapping, where `MADV_DONTNEED` drops resident pages and leaves
            // untouched pages unbacked.
            let advised = unsafe {
                libc::madvise(
                    self.pointer.add(range.start).cast(),
                    range.len(),
                    libc::MADV_DONTNEED,
                )
            };
            if advised == 0 {
                return Ok(());
            }
        }
        self.write_zeros(offset, length)
    }

    pub(crate) fn allocation_size(&self) -> u64 {
        u64::try_from(self.size).unwrap_or(u64::MAX)
    }

    pub(crate) fn size(&self) -> u64 {
        self.allocation_size()
            .min(super::machine::USER_ADDRESS_BYTES)
    }

    pub(crate) fn protect_host(
        &self,
        offset: u64,
        length: u64,
        prot: i32,
    ) -> std::result::Result<(), Errno> {
        let range = self.range(offset, length).map_err(|_| Errno::ENOMEM)?;
        if range.is_empty() {
            return Ok(());
        }
        let rc = unsafe { libc::mprotect(self.pointer.add(range.start).cast(), range.len(), prot) };
        if rc != 0 {
            return Err(Errno::last_os(Errno::ENOMEM));
        }
        if prot != (libc::PROT_READ | libc::PROT_WRITE) {
            self.custom_mappings.store(true, Ordering::Release);
        }
        Ok(())
    }

    /// Applies guest advice only to a checked payload range, never supervisor memory.
    pub(crate) fn advise(
        &self,
        offset: u64,
        length: u64,
        advice: i32,
    ) -> std::result::Result<(), Errno> {
        let range = self.range(offset, length).map_err(|_| Errno::ENOMEM)?;
        // SAFETY: the broker has checked that this range is guest-mapped.
        if unsafe { libc::madvise(self.pointer.add(range.start).cast(), range.len(), advice) } != 0
        {
            return Err(Errno::last_os(Errno::ENOMEM));
        }
        // Advice can change VMA flags, protections or inheritance. Exec must
        // replace these VMAs rather than merely discarding their contents.
        self.custom_mappings.store(true, Ordering::Release);
        Ok(())
    }

    pub(crate) fn discard_supervisor(&self, offset: u64, length: u64) {
        if let Ok(range) = self.supervisor_range(offset, length)
            && !range.is_empty()
        {
            unsafe {
                let _ = libc::madvise(
                    self.pointer.add(range.start).cast(),
                    range.len(),
                    libc::MADV_DONTNEED,
                );
            }
        }
    }

    pub(crate) fn restore_anonymous(&self, offset: u64, length: u64) -> Result<()> {
        let range = self.range(offset, length)?;
        if range.is_empty() {
            return Ok(());
        }
        let mapped = unsafe {
            libc::mmap(
                self.pointer.add(range.start).cast(),
                range.len(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            return Err(io::Error::last_os_error()).context("restore anonymous guest mapping");
        }
        Ok(())
    }

    pub(crate) fn map_host(
        &self,
        offset: u64,
        length: u64,
        prot: i32,
        flags: i32,
        fd: RawFd,
        file_offset: libc::off_t,
    ) -> std::result::Result<(), Errno> {
        let range = self.range(offset, length).map_err(|_| Errno::ENOMEM)?;
        let mapped = unsafe {
            libc::mmap(
                self.pointer.add(range.start).cast(),
                range.len(),
                prot,
                flags | libc::MAP_FIXED,
                fd,
                file_offset,
            )
        };
        if mapped == libc::MAP_FAILED {
            return Err(Errno::last_os(Errno::ENOMEM));
        }
        self.custom_mappings.store(true, Ordering::Release);
        Ok(())
    }

    pub(crate) fn attach_shm(
        &self,
        offset: u64,
        length: u64,
        shmid: i32,
        shmflg: i32,
    ) -> std::result::Result<(), Errno> {
        let range = self.range(offset, length).map_err(|_| Errno::EINVAL)?;
        let host_flags = (shmflg & !(libc::SHM_RND | libc::SHM_EXEC)) | libc::SHM_REMAP;
        let attached =
            unsafe { libc::shmat(shmid, self.pointer.add(range.start).cast(), host_flags) };
        if attached.addr() == usize::MAX {
            return Err(Errno::last_os(Errno::ENOMEM));
        }
        self.custom_mappings.store(true, Ordering::Release);
        Ok(())
    }

    pub(crate) fn detach_shm(&self, offset: u64) -> std::result::Result<(), Errno> {
        let range = self.range(offset, 0).map_err(|_| Errno::EINVAL)?;
        if unsafe { libc::shmdt(self.pointer.add(range.start).cast()) } != 0 {
            return Err(Errno::last_os(Errno::EINVAL));
        }
        Ok(())
    }

    fn refill_unmapped_hole(&self, offset: u64, length: u64) -> bool {
        let Ok(range) = self.range(offset, length) else {
            return false;
        };
        if range.is_empty() {
            return false;
        }
        let mapped = unsafe {
            libc::mmap(
                self.pointer.add(range.start).cast(),
                range.len(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE
                    | libc::MAP_ANONYMOUS
                    | libc::MAP_NORESERVE
                    | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        mapped != libc::MAP_FAILED
    }

    pub(crate) fn remap_host(
        &self,
        old_offset: u64,
        old_length: u64,
        new_offset: u64,
        new_length: u64,
        extra_flags: i32,
        keep_source: bool,
    ) -> std::result::Result<(), (Errno, bool, bool)> {
        let old_range = self
            .range(old_offset, old_length)
            .map_err(|_| (Errno::EFAULT, false, false))?;
        let new_range = self
            .range(new_offset, new_length)
            .map_err(|_| (Errno::ENOMEM, false, false))?;
        self.custom_mappings.store(true, Ordering::Release);
        let moved = unsafe {
            libc::mremap(
                self.pointer.add(old_range.start).cast(),
                old_range.len(),
                new_range.len(),
                libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED | extra_flags,
                self.pointer.add(new_range.start).cast::<libc::c_void>(),
            )
        };
        if moved == libc::MAP_FAILED {
            let errno = Errno::last_os(Errno::ENOMEM);
            let shrunk_tail = !keep_source
                && new_length < old_length
                && self.refill_unmapped_hole(old_offset + new_length, old_length - new_length);
            let unmapped_dest = self.refill_unmapped_hole(new_offset, new_length);
            return Err((errno, shrunk_tail, unmapped_dest));
        }
        if !keep_source {
            let _ = self.restore_anonymous(old_offset, old_length);
        }
        Ok(())
    }

    /// Grows a host VMA into guest-unmapped space, preserving its advice flags.
    pub(crate) fn grow_host(
        &self,
        offset: u64,
        old_length: u64,
        new_length: u64,
    ) -> std::result::Result<(), Errno> {
        let old = self.range(offset, old_length).map_err(|_| Errno::EFAULT)?;
        let new = self.range(offset, new_length).map_err(|_| Errno::ENOMEM)?;
        if new.len() <= old.len() {
            return Err(Errno::EINVAL);
        }
        self.custom_mappings.store(true, Ordering::Release);
        // The guest-unmapped tail is still a host reservation. Temporarily
        // release it so the kernel can extend this VMA without moving it.
        if unsafe { libc::munmap(self.pointer.add(old.end).cast(), new.end - old.end) } != 0 {
            return Err(Errno::last_os(Errno::ENOMEM));
        }
        let grown =
            unsafe { libc::mremap(self.pointer.add(old.start).cast(), old.len(), new.len(), 0) };
        if grown == libc::MAP_FAILED {
            let errno = Errno::last_os(Errno::ENOMEM);
            self.restore_anonymous(offset + old_length, new_length - old_length)
                .map_err(|_| Errno::ENOMEM)?;
            return Err(errno);
        }
        Ok(())
    }

    /// Host address of the start of guest physical memory.
    pub(crate) fn base(&self) -> u64 {
        u64::try_from(self.pointer.addr()).unwrap_or(u64::MAX)
    }

    fn supervisor_range(&self, offset: u64, length: u64) -> Result<Range<usize>> {
        let end = offset
            .checked_add(length)
            .context("guest buffer overflows the address space")?;
        if end > self.allocation_size() {
            bail!("guest buffer {offset:#x}+{length:#x} is outside guest memory");
        }
        let start = usize::try_from(offset).context("guest buffer offset")?;
        Ok(start..start + usize::try_from(length).context("guest buffer length")?)
    }

    fn range(&self, offset: u64, length: u64) -> Result<Range<usize>> {
        if offset < super::machine::RESERVED_END {
            bail!("guest buffer {offset:#x} is in reserved memory");
        }
        let end = offset
            .checked_add(length)
            .context("guest buffer overflows the address space")?;
        if end > self.size() {
            bail!("guest buffer {offset:#x}+{length:#x} is outside guest memory");
        }
        self.supervisor_range(offset, length)
    }

    fn copy_out(&self, range: Range<usize>) -> Vec<u8> {
        let mut buffer = vec![0u8; range.len()];
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.pointer.add(range.start),
                buffer.as_mut_ptr(),
                range.len(),
            );
        }
        buffer
    }

    fn copy_in(&self, range: Range<usize>, bytes: &[u8]) {
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.pointer.add(range.start),
                bytes.len(),
            );
        }
    }

    fn try_copy_out(&self, range: Range<usize>) -> Result<Vec<u8>> {
        if !self.custom_mappings.load(Ordering::Acquire) || range.is_empty() {
            return Ok(self.copy_out(range));
        }
        let mut buffer = vec![0u8; range.len()];
        let local = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: buffer.len(),
        };
        let remote = libc::iovec {
            iov_base: unsafe { self.pointer.add(range.start) }.cast(),
            iov_len: range.len(),
        };
        let copied = unsafe {
            libc::process_vm_readv(libc::getpid(), &raw const local, 1, &raw const remote, 1, 0)
        };
        if copied < 0 || usize::try_from(copied).ok() != Some(range.len()) {
            bail!("guest buffer read faulted");
        }
        Ok(buffer)
    }

    fn try_copy_in(&self, range: Range<usize>, bytes: &[u8]) -> Result<()> {
        if !self.custom_mappings.load(Ordering::Acquire) || bytes.is_empty() {
            self.copy_in(range, bytes);
            return Ok(());
        }
        let local = libc::iovec {
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        };
        let remote = libc::iovec {
            iov_base: unsafe { self.pointer.add(range.start) }.cast(),
            iov_len: bytes.len(),
        };
        let copied = unsafe {
            libc::process_vm_writev(libc::getpid(), &raw const local, 1, &raw const remote, 1, 0)
        };
        if copied < 0 || usize::try_from(copied).ok() != Some(bytes.len()) {
            bail!("guest buffer write faulted");
        }
        Ok(())
    }

    fn write_zeros_safe(&self, range: Range<usize>) -> Result<()> {
        const CHUNK: usize = 4096;
        let zeros = [0u8; CHUNK];
        let mut cursor = range.start;
        while cursor < range.end {
            let step = (range.end - cursor).min(CHUNK);
            self.try_copy_in(cursor..cursor + step, &zeros[..step])?;
            cursor += step;
        }
        Ok(())
    }

    /// Host address of a guest buffer of `length` bytes.
    pub(crate) fn address(&self, offset: u64, length: u64) -> Result<u64> {
        self.range(offset, length)?;
        Ok(self.base() + offset)
    }

    pub(crate) fn translated_address(&self, offset: u64, length: u64) -> u64 {
        if offset == 0 {
            return 0;
        }
        self.address(offset, length).unwrap_or(1)
    }

    pub(crate) fn read(&self, offset: u64, length: u64) -> Result<Vec<u8>> {
        self.try_copy_out(self.range(offset, length)?)
    }

    pub(crate) fn read_supervisor(&self, offset: u64, length: u64) -> Result<Vec<u8>> {
        Ok(self.copy_out(self.supervisor_range(offset, length)?))
    }

    pub(crate) fn read_supervisor_u64(&self, offset: u64) -> Result<u64> {
        let bytes = self.read_supervisor(offset, 8)?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8])))
    }

    pub(crate) fn write(&self, offset: u64, bytes: &[u8]) -> Result<()> {
        let length = u64::try_from(bytes.len()).context("guest buffer length")?;
        self.try_copy_in(self.range(offset, length)?, bytes)
    }

    pub(crate) fn write_supervisor(&self, offset: u64, bytes: &[u8]) -> Result<()> {
        let length = u64::try_from(bytes.len()).context("guest buffer length")?;
        self.copy_in(self.supervisor_range(offset, length)?, bytes);
        Ok(())
    }

    pub(crate) fn write_zeros(&self, offset: u64, length: u64) -> Result<()> {
        let range = self.range(offset, length)?;
        if self.custom_mappings.load(Ordering::Acquire) {
            return self.write_zeros_safe(range);
        }
        // SAFETY: `range` is within the mapping.
        unsafe {
            std::ptr::write_bytes(self.pointer.add(range.start), 0, range.len());
        }
        Ok(())
    }

    /// Makes instructions the VMM or the host kernel wrote to a guest buffer
    /// visible to instruction fetch, which is not coherent with data writes
    /// on every architecture.
    pub(crate) fn synchronize_instructions(&self, offset: u64, length: u64) -> Result<()> {
        let range = self.range(offset, length)?;
        // SAFETY: `range` is within the mapping.
        let synchronized = unsafe {
            clear_cache::clear_cache(self.pointer.add(range.start), self.pointer.add(range.end))
        };
        if !synchronized {
            bail!("synchronize guest instructions at {offset:#x}+{length:#x}");
        }
        Ok(())
    }

    pub(crate) fn write_u64(&self, offset: u64, value: u64) -> Result<()> {
        self.write(offset, &value.to_le_bytes())
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn write_supervisor_u64(&self, offset: u64, value: u64) -> Result<()> {
        self.write_supervisor(offset, &value.to_le_bytes())
    }

    pub(crate) fn write_supervisor_u64_atomic(&self, offset: u64, value: u64) -> Result<()> {
        let range = self.supervisor_range(offset, 8)?;
        if !offset.is_multiple_of(8) {
            bail!("supervisor word {offset:#x} is not 8-byte aligned");
        }
        // SAFETY: `range` is 8 valid bytes inside the guest mapping.
        let target = unsafe { self.pointer.add(range.start) };
        if !target.addr().is_multiple_of(align_of::<AtomicU64>()) {
            bail!("supervisor word {offset:#x} is not 8-byte aligned");
        }
        #[allow(clippy::cast_ptr_alignment)]
        // SAFETY: `target` was verified to be 8-byte aligned and valid for 8 bytes.
        unsafe { AtomicU64::from_ptr(target.cast::<u64>()) }.store(value, Ordering::Release);
        Ok(())
    }

    /// Writes a 32-bit word visible to concurrent guest threads and futexes,
    /// returning its host address.
    pub(crate) fn write_u32_atomic(&self, offset: u64, value: u32) -> Result<u64> {
        let range = self.range(offset, 4)?;
        if !offset.is_multiple_of(4) {
            bail!("guest word {offset:#x} is not 4-byte aligned");
        }
        if self.custom_mappings.load(Ordering::Acquire) {
            self.try_copy_in(range, &value.to_le_bytes())?;
            std::sync::atomic::fence(Ordering::Release);
            return Ok(self.base() + offset);
        }
        // SAFETY: `range` is 4 valid bytes inside the guest mapping.
        let target = unsafe { self.pointer.add(range.start) };
        if !target.addr().is_multiple_of(align_of::<AtomicU32>()) {
            bail!("guest word {offset:#x} is not 4-byte aligned");
        }
        #[allow(clippy::cast_ptr_alignment)]
        // SAFETY: `target` was just verified to be 4-byte aligned and valid for 4 bytes.
        unsafe { AtomicU32::from_ptr(target.cast::<u32>()) }.store(value, Ordering::Release);
        Ok(self.base() + offset)
    }

    /// Replaces the guest word with `new` if it holds `current`, returning the
    /// word found. A direct access could fault with custom mappings, so then
    /// the word is copied in and out, and the exchange is not atomic.
    pub(crate) fn compare_exchange_u32(
        &self,
        offset: u64,
        current: u32,
        new: u32,
    ) -> Result<Exchange> {
        let range = self.range(offset, 4)?;
        if !offset.is_multiple_of(4) {
            bail!("guest word {offset:#x} is not 4-byte aligned");
        }
        if self.custom_mappings.load(Ordering::Acquire) {
            let found = self.try_copy_out(range.clone())?;
            let found = u32::from_le_bytes(found.try_into().unwrap_or_default());
            if found == current {
                self.try_copy_in(range, &new.to_le_bytes())?;
            }
            return Ok(Exchange {
                found,
                atomic: false,
            });
        }
        // SAFETY: `range` is 4 valid bytes inside the guest mapping.
        let target = unsafe { self.pointer.add(range.start) };
        if !target.addr().is_multiple_of(align_of::<AtomicU32>()) {
            bail!("guest word {offset:#x} is not 4-byte aligned");
        }
        #[allow(clippy::cast_ptr_alignment)]
        // SAFETY: `target` was just verified to be 4-byte aligned and valid for 4 bytes.
        let word = unsafe { AtomicU32::from_ptr(target.cast::<u32>()) };
        let found = word
            .compare_exchange(current, new, Ordering::AcqRel, Ordering::Acquire)
            .unwrap_or_else(|found| found);
        Ok(Exchange {
            found,
            atomic: true,
        })
    }

    fn read_cstring(&self, offset: u64, limit: usize) -> std::result::Result<Vec<u8>, Errno> {
        if offset < super::machine::RESERVED_END || offset >= self.size() {
            return Err(Errno::EFAULT);
        }
        let (Ok(start), Ok(available)) = (
            usize::try_from(offset),
            usize::try_from(self.size() - offset),
        ) else {
            return Err(Errno::EFAULT);
        };
        let max = available.min(limit);
        let mut bytes = Vec::new();
        if self.custom_mappings.load(Ordering::Acquire) {
            let end = start + max;
            let mut cursor = start;
            while cursor < end {
                let page_end = ((cursor + 4096) & !4095).min(end);
                let chunk = self
                    .try_copy_out(cursor..page_end)
                    .map_err(|_| Errno::EFAULT)?;
                if let Some(pos) = chunk.iter().position(|&b| b == 0) {
                    bytes.extend_from_slice(&chunk[..pos]);
                    return Ok(bytes);
                }
                bytes.extend_from_slice(&chunk);
                cursor = page_end;
            }
        } else {
            for index in 0..max {
                let byte = unsafe { std::ptr::read_volatile(self.pointer.add(start + index)) };
                if byte == 0 {
                    return Ok(bytes);
                }
                bytes.push(byte);
            }
        }
        if available < limit {
            Err(Errno::EFAULT)
        } else {
            Err(Errno::ENAMETOOLONG)
        }
    }

    pub(crate) fn read_comm(&self, offset: u64) -> std::result::Result<[u8; 16], Errno> {
        if offset < super::machine::RESERVED_END || offset >= self.size() {
            return Err(Errno::EFAULT);
        }
        let (Ok(start), Ok(available)) = (
            usize::try_from(offset),
            usize::try_from(self.size() - offset),
        ) else {
            return Err(Errno::EFAULT);
        };
        let mut comm = [0u8; 16];
        let max = available.min(15);
        if self.custom_mappings.load(Ordering::Acquire) {
            let end = start + max;
            let mut cursor = start;
            let mut written = 0;
            while cursor < end {
                let page_end = ((cursor + 4096) & !4095).min(end);
                let chunk = self
                    .try_copy_out(cursor..page_end)
                    .map_err(|_| Errno::EFAULT)?;
                for &byte in &chunk {
                    comm[written] = byte;
                    written += 1;
                    if byte == 0 {
                        return Ok(comm);
                    }
                }
                cursor = page_end;
            }
        } else {
            for (index, slot) in comm.iter_mut().take(max).enumerate() {
                let byte = unsafe { std::ptr::read_volatile(self.pointer.add(start + index)) };
                *slot = byte;
                if byte == 0 {
                    return Ok(comm);
                }
            }
        }
        if available >= 15 {
            Ok(comm)
        } else {
            Err(Errno::EFAULT)
        }
    }

    pub(crate) fn read_cstring_vec(
        &self,
        offset: u64,
        max_count: usize,
        max_item_len: usize,
        max_total_bytes: usize,
    ) -> std::result::Result<Vec<OsString>, Errno> {
        let mut values = Vec::new();
        if offset == 0 {
            return Ok(values);
        }
        let mut total = 0usize;
        for index in 0..max_count {
            let Some(slot) = u64::try_from(index)
                .ok()
                .and_then(|i| i.checked_mul(8))
                .and_then(|bytes| offset.checked_add(bytes))
            else {
                return Err(Errno::EFAULT);
            };
            let Ok(bytes) = self.read(slot, 8) else {
                return Err(Errno::EFAULT);
            };
            let at = u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]));
            if at == 0 {
                return Ok(values);
            }
            let item = self.read_cstring(at, max_item_len).map_err(|errno| {
                if errno == Errno::ENAMETOOLONG {
                    Errno::E2BIG
                } else {
                    errno
                }
            })?;
            total = total.saturating_add(item.len() + 1);
            if total > max_total_bytes {
                return Err(Errno::E2BIG);
            }
            values.push(OsString::from_vec(item));
        }
        Err(Errno::E2BIG)
    }
}

impl Drop for GuestMemory {
    fn drop(&mut self) {
        if self.owned.load(Ordering::Relaxed) {
            // SAFETY: `pointer` and `size` came from `mmap` and are owned here.
            unsafe {
                libc::munmap(self.pointer.cast(), self.size);
            }
        }
    }
}
