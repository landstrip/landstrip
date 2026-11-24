// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::super::ErrnoExt;
use super::super::fds::GuestFd;
use super::super::machine::{
    Machine, PAGE_BYTES, RESERVED_END, Regs, STACK_TOP, USER_ADDRESS_BYTES,
};
use super::super::memory::GuestMemory;
use super::{GuestReg, Process, SyscallArgs, WORD_SIZE};
use anyhow::Result;
#[cfg(target_arch = "x86_64")]
use linux_raw_sys::general::MAP_32BIT;
use linux_raw_sys::general::{
    MAP_ANONYMOUS, MAP_FIXED, MAP_FIXED_NOREPLACE, MAP_PRIVATE, MAP_SHARED, MAP_SHARED_VALIDATE,
    MAP_TYPE, MREMAP_DONTUNMAP, MREMAP_FIXED, MREMAP_MAYMOVE,
};
use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use syscalls::{Errno, Sysno};

#[cfg(target_arch = "x86_64")]
const MAP_32BIT_CEILING: u64 = 0x8000_0000;
#[cfg(target_arch = "x86_64")]
const VALID_MPROTECT_FLAGS: u64 = 0x7;
#[cfg(target_arch = "aarch64")]
const VALID_MPROTECT_FLAGS: u64 = 0x17;
const MAPPING_RESERVE: u64 = 0x0100_0000;
pub(super) const MAPPING_CEILING: u64 = STACK_TOP - MAPPING_RESERVE;

#[derive(Clone, Copy, PartialEq, Eq)]
enum MappingKind {
    Anonymous,
    HostBacked,
    SysvShm { base: u64 },
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct MappingMeta {
    kind: MappingKind,
    prot: u32,
    shared: bool,
    /// Host VMA attributes must be reset when this range is reused.
    advised: bool,
    dont_fork: bool,
}

impl MappingMeta {
    const fn anon(prot: u32) -> Self {
        Self {
            kind: MappingKind::Anonymous,
            prot,
            shared: false,
            advised: false,
            dont_fork: false,
        }
    }

    const fn needs_host_restore(self) -> bool {
        !matches!(self.kind, MappingKind::Anonymous) || self.advised
    }

    const fn relocated(mut self, old_addr: u64, new_addr: u64) -> Self {
        if let MappingKind::SysvShm { base } = self.kind {
            self.kind = if let Some(offset) = old_addr.checked_sub(base)
                && let Some(relocated_base) = new_addr.checked_sub(offset)
                && relocated_base >= RESERVED_END
            {
                MappingKind::SysvShm {
                    base: relocated_base,
                }
            } else {
                MappingKind::HostBacked
            };
        }
        self
    }

    const fn format_perms(self) -> [u8; 4] {
        let r = if self.prot & libc::PROT_READ.cast_unsigned() != 0 {
            b'r'
        } else {
            b'-'
        };
        let w = if self.prot & libc::PROT_WRITE.cast_unsigned() != 0 {
            b'w'
        } else {
            b'-'
        };
        let x = if self.prot & libc::PROT_EXEC.cast_unsigned() != 0 {
            b'x'
        } else {
            b'-'
        };
        let s = if self.shared { b's' } else { b'p' };
        [r, w, x, s]
    }
}

#[derive(Clone)]
pub(super) struct AddressSpace {
    heap_floor: u64,
    break_point: u64,
    regions: BTreeMap<u64, (u64, MappingMeta)>,
}

impl AddressSpace {
    pub(super) const fn page_align_len(size: u64) -> Option<u64> {
        match size.checked_add(PAGE_BYTES - 1) {
            Some(aligned) => Some(aligned & !(PAGE_BYTES - 1)),
            None => None,
        }
    }

    pub(super) fn new(payload_end: u64, segments: &[(u64, u64, u32)]) -> Self {
        let heap_floor = Self::page_align_len(payload_end).unwrap_or(u64::MAX);
        let mut space = Self {
            heap_floor,
            break_point: heap_floor,
            regions: BTreeMap::new(),
        };
        let rw = (libc::PROT_READ | libc::PROT_WRITE).cast_unsigned();
        for &(start, end, prot) in segments {
            space.insert_segment(start, end, prot);
        }
        space.insert_range(MAPPING_CEILING, USER_ADDRESS_BYTES, MappingMeta::anon(rw));
        space
    }

    fn insert_segment(&mut self, start: u64, end: u64, prot: u32) {
        if start >= end {
            return;
        }
        let overlapped = self.take_overlapping(start, end);
        let mut cursor = start;
        for (ov_start, ov_end, ov_meta) in overlapped {
            if cursor < ov_start {
                self.insert_range(cursor, ov_start, MappingMeta::anon(prot));
            }
            self.insert_range(ov_start, ov_end, MappingMeta::anon(ov_meta.prot | prot));
            cursor = ov_end;
        }
        if cursor < end {
            self.insert_range(cursor, end, MappingMeta::anon(prot));
        }
    }

    pub(super) const fn break_point(&self) -> u64 {
        self.break_point
    }

    pub(super) fn dont_fork_ranges(&self) -> Vec<(u64, u64)> {
        self.regions
            .iter()
            .filter_map(|(&start, &(end, meta))| meta.dont_fork.then_some((start, end)))
            .collect()
    }

    pub(super) fn writable_private_ranges(&self) -> Vec<(u64, u64)> {
        self.regions
            .iter()
            .filter_map(|(&start, &(end, meta))| {
                (!meta.shared && meta.prot & libc::PROT_WRITE.cast_unsigned() != 0)
                    .then_some((start, end))
            })
            .collect()
    }

    pub(super) fn sync_page_tables(&self, machine: &Machine) -> Result<()> {
        for (&start, &(end, meta)) in &self.regions {
            if start < end {
                let hprot = Process::host_prot(meta.prot);
                if hprot != (libc::PROT_READ | libc::PROT_WRITE) {
                    machine
                        .memory
                        .protect_host(start, end - start, hprot)
                        .map_err(|errno| io::Error::from_raw_os_error(errno.into_raw()))?;
                }
                machine.protect_pages(start, end - start, meta.prot)?;
            }
        }
        Ok(())
    }

    const fn heap_end(&self) -> u64 {
        match Self::page_align_len(self.break_point) {
            Some(end) => end,
            None => u64::MAX,
        }
    }

    pub(super) fn format_proc_maps(&self, exe: &Path) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let heap_end = self.heap_end();
        for (&start, &(end, meta)) in &self.regions {
            let perms_bytes = meta.format_perms();
            let perms = std::str::from_utf8(&perms_bytes).unwrap_or("rwxp");
            if start >= MAPPING_CEILING {
                let shown_end = end.min(STACK_TOP);
                if start < shown_end {
                    let _ = writeln!(
                        out,
                        "{start:08x}-{shown_end:08x} {perms} 00000000 00:00 0                          [stack]",
                    );
                }
            } else if start >= self.heap_floor && end <= heap_end {
                let _ = writeln!(
                    out,
                    "{start:08x}-{end:08x} {perms} 00000000 00:00 0                          [heap]"
                );
            } else if end <= self.heap_floor {
                let _ = writeln!(
                    out,
                    "{:08x}-{:08x} {perms} 00000000 00:00 0                          {}",
                    start,
                    end,
                    exe.display()
                );
            } else {
                let _ = writeln!(out, "{start:08x}-{end:08x} {perms} 00000000 00:00 0");
            }
        }
        out
    }

    fn regions_overlap(&self, start: u64, end: u64) -> bool {
        start < end
            && self
                .regions
                .range(..end)
                .next_back()
                .is_some_and(|(_, &(entry_end, _))| entry_end > start)
    }

    pub(super) fn overlaps(&self, start: u64, end: u64) -> bool {
        self.regions_overlap(start, end)
    }

    fn is_fully_mapped(&self, start: u64, end: u64) -> bool {
        let mut cursor = start;
        while cursor < end {
            if let Some((_, &(entry_end, _))) = self.regions.range(..=cursor).next_back()
                && entry_end > cursor
            {
                cursor = entry_end;
                continue;
            }
            return false;
        }
        true
    }

    fn covering_meta(&self, start: u64, end: u64) -> Option<MappingMeta> {
        let (_, &(mut cursor, mut meta)) = self.regions.range(..=start).next_back()?;
        while cursor < end {
            let &(next_end, next) = self.regions.get(&cursor)?;
            if next.kind != meta.kind
                || next.prot != meta.prot
                || next.shared != meta.shared
                || next.dont_fork != meta.dont_fork
            {
                return None;
            }
            // Advice bookkeeping can stay split after the kernel has merged
            // VMAs again. Let host mremap check the actual VMA boundaries.
            meta.advised |= next.advised;
            cursor = next_end;
        }
        Some(meta)
    }

    fn take_overlapping(&mut self, start: u64, end: u64) -> Vec<(u64, u64, MappingMeta)> {
        if start >= end {
            return Vec::new();
        }
        let mut keys = Vec::new();
        if let Some((&prev_start, &(prev_end, _))) = self.regions.range(..start).next_back()
            && prev_end > start
        {
            keys.push(prev_start);
        }
        keys.extend(self.regions.range(start..end).map(|(&key, _)| key));
        let mut removed = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some((entry_end, meta)) = self.regions.remove(&key) {
                removed.push((key.max(start), entry_end.min(end), meta));
                if key < start {
                    self.regions.insert(key, (start, meta));
                }
                if entry_end > end {
                    self.regions.insert(end, (entry_end, meta));
                }
            }
        }
        removed
    }

    pub(super) fn remove_range(&mut self, start: u64, end: u64) -> bool {
        self.take_overlapping(start, end)
            .into_iter()
            .any(|(_, _, meta)| meta.needs_host_restore())
    }

    fn has_shm_base(&self, base: u64) -> bool {
        self.regions
            .values()
            .any(|&(_, meta)| meta.kind == MappingKind::SysvShm { base })
    }

    fn take_shm_segments(&mut self, base: u64) -> Vec<(u64, u64)> {
        let starts: Vec<u64> = self
            .regions
            .iter()
            .filter_map(|(&start, &(_, meta))| {
                (meta.kind == MappingKind::SysvShm { base }).then_some(start)
            })
            .collect();
        let mut segments = Vec::with_capacity(starts.len());
        for start in starts {
            if let Some((end, _)) = self.regions.remove(&start) {
                segments.push((start, end));
            }
        }
        segments
    }

    fn insert_range(&mut self, start: u64, end: u64, meta: MappingMeta) -> bool {
        let had_host = self.remove_range(start, end);
        if start >= end {
            return had_host;
        }
        if meta.kind == MappingKind::Anonymous && !meta.shared && !meta.advised {
            let mut merged_start = start;
            let mut merged_end = end;
            if let Some((&pred_start, &(pred_end, pred_meta))) =
                self.regions.range(..=start).next_back()
                && pred_end == start
                && start != self.heap_floor
                && pred_meta == meta
            {
                merged_start = pred_start;
                self.regions.remove(&pred_start);
            }
            if let Some(&(succ_end, succ_meta)) = self.regions.get(&end)
                && end != self.heap_floor
                && succ_meta == meta
            {
                merged_end = succ_end;
                self.regions.remove(&end);
            }
            self.regions.insert(merged_start, (merged_end, meta));
        } else {
            self.regions.insert(start, (end, meta));
        }
        had_host
    }

    fn set_prot(&mut self, start: u64, end: u64, prot: u32) {
        let slices = self.take_overlapping(start, end);
        for (seg_start, seg_end, mut meta) in slices {
            meta.prot = prot;
            self.insert_range(seg_start, seg_end, meta);
        }
    }

    fn find_free_top_down(&self, length: u64, floor: u64, ceiling: u64) -> Option<u64> {
        let low = floor.max(RESERVED_END);
        if length == 0 || ceiling <= low || ceiling - low < length {
            return None;
        }
        let occupied: Vec<(u64, u64)> = self
            .regions
            .range(..ceiling)
            .filter_map(|(&s, &(e, _))| (e > low).then_some((s.max(low), e.min(ceiling))))
            .collect();
        let mut cursor = ceiling;
        for &(s, e) in occupied.iter().rev() {
            if e < cursor && cursor - e >= length {
                return Some(cursor - length);
            }
            cursor = cursor.min(s);
        }
        (cursor >= low && cursor - low >= length).then(|| cursor - length)
    }
}

impl Process {
    const fn host_prot(prot: u32) -> i32 {
        let rwx = prot & 0x7;
        if rwx == 0 {
            libc::PROT_NONE
        } else if rwx & libc::PROT_WRITE.cast_unsigned() != 0 {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        }
    }

    pub(super) fn mmap(&self, registers: &Regs, memory: &GuestMemory) -> u64 {
        let [hint, size, protection, flags, fd, offset] = registers.arguments();
        if size == 0 {
            return Errno::EINVAL.negated();
        }
        let Some(length) = AddressSpace::page_align_len(size) else {
            return Errno::ENOMEM.negated();
        };
        let map_type = GuestReg(flags).as_u32() & MAP_TYPE;
        if !matches!(map_type, MAP_SHARED | MAP_PRIVATE | MAP_SHARED_VALIDATE) {
            return Errno::EINVAL.negated();
        }
        let anonymous = flags & u64::from(MAP_ANONYMOUS) != 0;
        if !anonymous && !offset.is_multiple_of(PAGE_BYTES) {
            return Errno::EINVAL.negated();
        }
        let mut space = self
            .space
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let address = match Self::select_mmap_address(&space, memory, hint, length, flags) {
            Ok(addr) => addr,
            Err(errno) => return errno.negated(),
        };
        let prot = GuestReg(protection).as_u32();
        let hprot = Self::host_prot(prot);
        let is_shared = matches!(map_type, MAP_SHARED | MAP_SHARED_VALIDATE);
        if anonymous && !is_shared {
            let removed = space.take_overlapping(address, address + length);
            let had_host = removed
                .iter()
                .any(|&(_, _, meta)| meta.needs_host_restore());
            let had_non_rw = removed.iter().any(|&(_, _, meta)| {
                Self::host_prot(meta.prot) != (libc::PROT_READ | libc::PROT_WRITE)
            });
            let cleared = if had_host {
                memory.restore_anonymous(address, length)
            } else {
                if had_non_rw
                    && memory
                        .protect_host(address, length, libc::PROT_READ | libc::PROT_WRITE)
                        .is_err()
                {
                    return Errno::ENOMEM.negated();
                }
                memory.discard(address, length)
            };
            if cleared.is_err() {
                let _ = self.machine.protect_pages(address, length, 0);
                return Errno::ENOMEM.negated();
            }
            if hprot != (libc::PROT_READ | libc::PROT_WRITE)
                && let Err(errno) = memory.protect_host(address, length, hprot)
            {
                let _ = self.machine.protect_pages(address, length, 0);
                return errno.negated();
            }
            if self.machine.protect_pages(address, length, prot).is_err() {
                return Errno::ENOMEM.negated();
            }
            space.insert_range(address, address + length, MappingMeta::anon(prot));
            return address;
        }
        if let Err(errno) =
            Self::install_host_mmap(memory, address, length, prot, flags, fd, offset, anonymous)
        {
            return errno.negated();
        }
        if self.machine.protect_pages(address, length, prot).is_err() {
            let _ = memory.restore_anonymous(address, length);
            return Errno::ENOMEM.negated();
        }
        space.insert_range(
            address,
            address + length,
            MappingMeta {
                kind: MappingKind::HostBacked,
                prot,
                shared: is_shared,
                advised: false,
                dont_fork: false,
            },
        );
        address
    }

    fn select_mmap_address(
        space: &AddressSpace,
        memory: &GuestMemory,
        hint: u64,
        length: u64,
        flags: u64,
    ) -> std::result::Result<u64, Errno> {
        if flags & u64::from(MAP_FIXED_NOREPLACE) != 0 {
            if !hint.is_multiple_of(PAGE_BYTES) {
                return Err(Errno::EINVAL);
            }
            let Some(end) = hint.checked_add(length) else {
                return Err(Errno::ENOMEM);
            };
            if hint < RESERVED_END || end > memory.size() {
                return Err(Errno::ENOMEM);
            }
            if space.overlaps(hint, end) {
                return Err(Errno::EEXIST);
            }
            return Ok(hint);
        }
        if flags & u64::from(MAP_FIXED) != 0 {
            if !hint.is_multiple_of(PAGE_BYTES) {
                return Err(Errno::EINVAL);
            }
            let Some(end) = hint.checked_add(length) else {
                return Err(Errno::ENOMEM);
            };
            if hint < RESERVED_END || end > memory.size() {
                return Err(Errno::ENOMEM);
            }
            return Ok(hint);
        }
        #[cfg(target_arch = "x86_64")]
        let ceiling = if flags & u64::from(MAP_32BIT) != 0 {
            MAP_32BIT_CEILING
        } else {
            MAPPING_CEILING
        };
        #[cfg(target_arch = "aarch64")]
        let ceiling = MAPPING_CEILING;
        if hint != 0 {
            let aligned_hint = hint & !(PAGE_BYTES - 1);
            if aligned_hint >= RESERVED_END
                && let Some(end) = aligned_hint.checked_add(length)
                && end <= ceiling
                && !space.overlaps(aligned_hint, end)
            {
                return Ok(aligned_hint);
            }
        }
        space
            .find_free_top_down(length, RESERVED_END, ceiling)
            .ok_or(Errno::ENOMEM)
    }

    #[allow(clippy::too_many_arguments)]
    fn install_host_mmap(
        memory: &GuestMemory,
        address: u64,
        length: u64,
        prot: u32,
        flags: u64,
        fd: u64,
        offset: u64,
        anonymous: bool,
    ) -> std::result::Result<(), Errno> {
        #[cfg(target_arch = "x86_64")]
        let placement_mask = u64::from(MAP_FIXED | MAP_FIXED_NOREPLACE | MAP_32BIT);
        #[cfg(target_arch = "aarch64")]
        let placement_mask = u64::from(MAP_FIXED | MAP_FIXED_NOREPLACE);

        if GuestReg(flags).as_u32() & MAP_TYPE == MAP_SHARED_VALIDATE && (flags >> 32) != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let (host_fd, file_offset) = if anonymous {
            (-1, 0)
        } else {
            let Some(descriptor) = GuestFd::from_reg(fd).valid() else {
                return Err(Errno::EBADF);
            };
            let Ok(off) = libc::off_t::try_from(offset) else {
                return Err(Errno::EINVAL);
            };
            (descriptor, off)
        };
        let host_prot = Self::host_prot(prot);
        let host_flags = GuestReg(flags & !placement_mask).as_i32();
        memory.map_host(address, length, host_prot, host_flags, host_fd, file_offset)
    }

    pub(super) fn munmap(&self, registers: &Regs, memory: &GuestMemory) -> u64 {
        let [address, size, ..] = registers.arguments();
        if !address.is_multiple_of(PAGE_BYTES) || size == 0 {
            return Errno::EINVAL.negated();
        }
        let Some(length) = AddressSpace::page_align_len(size) else {
            return Errno::EINVAL.negated();
        };
        let Some(end) = address.checked_add(length) else {
            return Errno::EINVAL.negated();
        };
        if end > memory.size() {
            return Errno::EINVAL.negated();
        }
        if address < RESERVED_END {
            return 0;
        }
        let mut space = self
            .space
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let removed = space.take_overlapping(address, end);
        for (seg_start, seg_end, meta) in removed {
            let seg_len = seg_end - seg_start;
            if meta.needs_host_restore() {
                let _ = memory.restore_anonymous(seg_start, seg_len);
            } else {
                if Self::host_prot(meta.prot) != (libc::PROT_READ | libc::PROT_WRITE) {
                    let _ =
                        memory.protect_host(seg_start, seg_len, libc::PROT_READ | libc::PROT_WRITE);
                }
                let _ = memory.discard(seg_start, seg_len);
            }
        }
        let _ = self.machine.protect_pages(address, length, 0);
        0
    }

    pub(super) fn mremap(&self, registers: &Regs, memory: &GuestMemory) -> u64 {
        let valid_flags = u64::from(MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP);
        let [old_addr, old_size, new_size, flags, new_addr, ..] = registers.arguments();
        if flags & !valid_flags != 0
            || (flags & u64::from(MREMAP_FIXED | MREMAP_DONTUNMAP) != 0
                && flags & u64::from(MREMAP_MAYMOVE) == 0)
            || !old_addr.is_multiple_of(PAGE_BYTES)
            || old_size == 0
            || new_size == 0
        {
            return Errno::EINVAL.negated();
        }
        let Some(old_len) = AddressSpace::page_align_len(old_size) else {
            return Errno::EINVAL.negated();
        };
        let Some(new_len) = AddressSpace::page_align_len(new_size) else {
            return Errno::ENOMEM.negated();
        };
        let Some(old_end) = old_addr.checked_add(old_len) else {
            return Errno::EINVAL.negated();
        };
        let mut space = self
            .space
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(meta) = space.covering_meta(old_addr, old_end) else {
            return Errno::EFAULT.negated();
        };
        let dont_unmap = flags & u64::from(MREMAP_DONTUNMAP) != 0;
        if dont_unmap && (old_len != new_len || meta.kind != MappingKind::Anonymous || meta.shared)
        {
            return Errno::EINVAL.negated();
        }
        if flags & u64::from(MREMAP_FIXED) != 0 {
            return self.mremap_fixed(
                &mut space, memory, old_addr, old_len, new_addr, new_len, meta, dont_unmap,
            );
        }
        if dont_unmap {
            let Some(dest) = space.find_free_top_down(new_len, RESERVED_END, MAPPING_CEILING)
            else {
                return Errno::ENOMEM.negated();
            };
            if let Err(errno) = memory.remap_host(
                old_addr,
                old_len,
                dest,
                new_len,
                libc::MREMAP_DONTUNMAP,
                true,
            ) {
                return errno.negated();
            }
            let _ = self.machine.protect_pages(dest, new_len, meta.prot);
            space.insert_range(dest, dest + new_len, meta);
            return dest;
        }
        self.mremap_resize(&mut space, memory, old_addr, old_len, new_len, flags, meta)
    }

    #[allow(clippy::too_many_arguments)]
    fn mremap_fixed(
        &self,
        space: &mut AddressSpace,
        memory: &GuestMemory,
        old_addr: u64,
        old_len: u64,
        new_addr: u64,
        new_len: u64,
        meta: MappingMeta,
        dont_unmap: bool,
    ) -> u64 {
        let old_end = old_addr + old_len;
        let Some(new_end) = new_addr.checked_add(new_len) else {
            return Errno::EINVAL.negated();
        };
        if !new_addr.is_multiple_of(PAGE_BYTES)
            || new_addr < RESERVED_END
            || new_end > memory.size()
            || !(old_end <= new_addr || new_end <= old_addr)
        {
            return Errno::EINVAL.negated();
        }
        let extra = if dont_unmap {
            libc::MREMAP_DONTUNMAP
        } else {
            0
        };
        if let Err(errno) =
            memory.remap_host(old_addr, old_len, new_addr, new_len, extra, dont_unmap)
        {
            return errno.negated();
        }
        if !dont_unmap {
            let _ = self.machine.protect_pages(old_addr, old_len, 0);
            space.remove_range(old_addr, old_end);
        }
        let _ = self.machine.protect_pages(new_addr, new_len, meta.prot);
        space.insert_range(new_addr, new_end, meta.relocated(old_addr, new_addr));
        new_addr
    }

    #[allow(clippy::too_many_arguments)]
    fn mremap_resize(
        &self,
        space: &mut AddressSpace,
        memory: &GuestMemory,
        old_addr: u64,
        old_len: u64,
        new_len: u64,
        flags: u64,
        meta: MappingMeta,
    ) -> u64 {
        let old_end = old_addr + old_len;
        if new_len == old_len {
            return old_addr;
        }
        if new_len < old_len {
            let tail_start = old_addr + new_len;
            let tail_len = old_len - new_len;
            space.remove_range(tail_start, old_end);
            if meta.needs_host_restore() {
                let _ = memory.restore_anonymous(tail_start, tail_len);
            } else {
                if Self::host_prot(meta.prot) != (libc::PROT_READ | libc::PROT_WRITE) {
                    let _ = memory.protect_host(
                        tail_start,
                        tail_len,
                        libc::PROT_READ | libc::PROT_WRITE,
                    );
                }
                let _ = memory.discard(tail_start, tail_len);
            }
            let _ = self.machine.protect_pages(tail_start, tail_len, 0);
            return old_addr;
        }
        if meta.needs_host_restore()
            && let Some(new_end) = old_addr.checked_add(new_len)
            && new_end <= memory.size()
            && !space.overlaps(old_end, new_end)
        {
            match memory.grow_host(old_addr, old_len, new_len) {
                Ok(()) => {
                    if self
                        .machine
                        .protect_pages(old_end, new_len - old_len, meta.prot)
                        .is_err()
                    {
                        return Errno::ENOMEM.negated();
                    }
                    space.insert_range(old_addr, new_end, meta);
                    return old_addr;
                }
                Err(errno) if flags & u64::from(MREMAP_MAYMOVE) == 0 => return errno.negated(),
                Err(_) => {} // Retry at a different guest address below.
            }
        }
        if meta.kind == MappingKind::Anonymous
            && !meta.shared
            && !meta.advised
            && let Some(new_end) = old_addr.checked_add(new_len)
            && new_end <= memory.size()
            && !space.overlaps(old_end, new_end)
        {
            let ext_len = new_len - old_len;
            if memory.discard(old_end, ext_len).is_err() {
                return Errno::ENOMEM.negated();
            }
            let hprot = Self::host_prot(meta.prot);
            if hprot != (libc::PROT_READ | libc::PROT_WRITE)
                && memory.protect_host(old_end, ext_len, hprot).is_err()
            {
                return Errno::ENOMEM.negated();
            }
            if self
                .machine
                .protect_pages(old_end, ext_len, meta.prot)
                .is_err()
            {
                return Errno::ENOMEM.negated();
            }
            space.insert_range(old_addr, new_end, meta);
            return old_addr;
        }
        if flags & u64::from(MREMAP_MAYMOVE) == 0 {
            return Errno::ENOMEM.negated();
        }
        let Some(dest) = space.find_free_top_down(new_len, RESERVED_END, MAPPING_CEILING) else {
            return Errno::ENOMEM.negated();
        };
        if let Err(errno) = memory.remap_host(old_addr, old_len, dest, new_len, 0, false) {
            return errno.negated();
        }
        let _ = self.machine.protect_pages(old_addr, old_len, 0);
        let _ = self.machine.protect_pages(dest, new_len, meta.prot);
        space.remove_range(old_addr, old_end);
        space.insert_range(dest, dest + new_len, meta.relocated(old_addr, dest));
        dest
    }

    pub(super) fn mprotect(&self, registers: &Regs, memory: &GuestMemory) -> u64 {
        let [address, size, protection, ..] = registers.arguments();
        if !address.is_multiple_of(PAGE_BYTES) || protection & !VALID_MPROTECT_FLAGS != 0 {
            return Errno::EINVAL.negated();
        }
        if size == 0 {
            return 0;
        }
        let Some(length) = AddressSpace::page_align_len(size) else {
            return Errno::ENOMEM.negated();
        };
        let Some(end) = address.checked_add(length) else {
            return Errno::ENOMEM.negated();
        };
        if address < RESERVED_END || end > memory.size() {
            return Errno::ENOMEM.negated();
        }
        let mut space = self
            .space
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !space.is_fully_mapped(address, end) {
            return Errno::ENOMEM.negated();
        }
        let prot = GuestReg(protection).as_u32();
        let hprot = Self::host_prot(prot);
        if let Err(errno) = memory.protect_host(address, length, hprot) {
            return errno.negated();
        }
        if self.machine.protect_pages(address, length, prot).is_err() {
            return Errno::ENOMEM.negated();
        }
        space.set_prot(address, end, prot);
        0
    }

    pub(super) fn madvise(&self, registers: &Regs, memory: &GuestMemory) -> u64 {
        let [address, size, advice, ..] = registers.arguments();
        if !address.is_multiple_of(PAGE_BYTES) {
            return Errno::EINVAL.negated();
        }
        let Some(length) = AddressSpace::page_align_len(size) else {
            return Errno::EINVAL.negated();
        };
        let Some(end) = address.checked_add(length) else {
            return Errno::EINVAL.negated();
        };
        // A zero-length call probes the host kernel's supported advice values.
        // In particular, invalid advice must fail even for an unmapped range.
        let valid = SyscallArgs::invoke(Sysno::madvise, &[0, 0, advice, 0, 0, 0]);
        if valid != 0 || length == 0 {
            return valid;
        }
        let advice = GuestReg(advice).as_i32();
        let persistent = matches!(
            advice,
            libc::MADV_NORMAL
                | libc::MADV_RANDOM
                | libc::MADV_SEQUENTIAL
                | libc::MADV_DONTFORK
                | libc::MADV_DOFORK
                | libc::MADV_WIPEONFORK
                | libc::MADV_KEEPONFORK
                | libc::MADV_DONTDUMP
                | libc::MADV_DODUMP
                | libc::MADV_MERGEABLE
                | libc::MADV_UNMERGEABLE
                | libc::MADV_HUGEPAGE
                | libc::MADV_NOHUGEPAGE
        );
        let mut space = self
            .space
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let regions: Vec<_> = space
            .regions
            .range(..end)
            .filter_map(|(&start, &(stop, meta))| {
                (stop > address).then_some((start.max(address), stop.min(end), meta))
            })
            .collect();
        let mut cursor = address;
        let mut hole = false;
        for (start, stop, mut meta) in regions {
            hole |= cursor < start;
            cursor = stop;
            // The host must be able to read executable guest pages for KVM,
            // even when the guest mapping itself has no read permission.
            if (advice == libc::MADV_POPULATE_READ
                && meta.prot & libc::PROT_READ.cast_unsigned() == 0)
                || (advice == libc::MADV_POPULATE_WRITE
                    && meta.prot & libc::PROT_WRITE.cast_unsigned() == 0)
            {
                return Errno::EINVAL.negated();
            }
            if let Err(errno) = memory.advise(start, stop - start, advice) {
                return errno.negated();
            }
            if persistent {
                meta.advised = true;
                if advice == libc::MADV_DONTFORK {
                    meta.dont_fork = true;
                } else if advice == libc::MADV_DOFORK {
                    meta.dont_fork = false;
                }
                space.insert_range(start, stop, meta);
            }
        }
        if hole || cursor < end {
            Errno::ENOMEM.negated()
        } else {
            0
        }
    }
    pub(super) fn msync(&self, registers: &Regs, memory: &GuestMemory) -> u64 {
        const VALID_FLAGS: i32 = libc::MS_ASYNC | libc::MS_INVALIDATE | libc::MS_SYNC;
        let [address, size, flags, ..] = registers.arguments();
        let ms_flags = GuestReg(flags).as_i32();
        if !address.is_multiple_of(PAGE_BYTES)
            || ms_flags & !VALID_FLAGS != 0
            || (ms_flags & libc::MS_ASYNC != 0 && ms_flags & libc::MS_SYNC != 0)
        {
            return Errno::EINVAL.negated();
        }
        if size == 0 {
            return 0;
        }
        let Some(length) = AddressSpace::page_align_len(size) else {
            return Errno::ENOMEM.negated();
        };
        let Some(end) = address.checked_add(length) else {
            return Errno::ENOMEM.negated();
        };
        if address < RESERVED_END || end > memory.size() {
            return Errno::ENOMEM.negated();
        }
        let mapped = self
            .space
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_fully_mapped(address, end);
        if !mapped {
            return Errno::ENOMEM.negated();
        }
        let Ok(host_addr) = memory.address(address, length) else {
            return Errno::ENOMEM.negated();
        };
        SyscallArgs::invoke(Sysno::msync, &[host_addr, length, flags, 0, 0, 0])
    }

    pub(super) fn mincore(&self, registers: &Regs, memory: &GuestMemory) -> u64 {
        let [address, size, vector, ..] = registers.arguments();
        if !address.is_multiple_of(PAGE_BYTES) {
            return Errno::EINVAL.negated();
        }
        if size == 0 {
            return 0;
        }
        let Some(length) = AddressSpace::page_align_len(size) else {
            return Errno::ENOMEM.negated();
        };
        let Some(end) = address.checked_add(length) else {
            return Errno::ENOMEM.negated();
        };
        let Ok(host) = memory.address(address, length) else {
            return Errno::ENOMEM.negated();
        };
        let space = self
            .space
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !space.is_fully_mapped(address, end) {
            return Errno::ENOMEM.negated();
        }
        let vector = memory.translated_address(vector, length / PAGE_BYTES);
        let result = SyscallArgs::invoke(Sysno::mincore, &[host, length, vector, 0, 0, 0]);
        drop(space);
        result
    }

    pub(super) fn brk(&self, requested: u64, memory: &GuestMemory) -> u64 {
        let mut space = self
            .space
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if requested < space.heap_floor || requested >= MAPPING_CEILING {
            return space.break_point;
        }
        let Some(new_end) = AddressSpace::page_align_len(requested) else {
            return space.break_point;
        };
        let old_end = space.heap_end();
        if new_end > old_end {
            if space.regions_overlap(old_end, new_end) {
                return space.break_point;
            }
            let rw = (libc::PROT_READ | libc::PROT_WRITE).cast_unsigned();
            if self
                .machine
                .protect_pages(old_end, new_end - old_end, rw)
                .is_err()
            {
                return space.break_point;
            }
            space.insert_range(old_end, new_end, MappingMeta::anon(rw));
        } else if new_end < old_end {
            if memory
                .restore_anonymous(new_end, old_end - new_end)
                .is_err()
            {
                return space.break_point;
            }
            if self
                .machine
                .protect_pages(new_end, old_end - new_end, 0)
                .is_err()
            {
                return space.break_point;
            }
            space.remove_range(new_end, old_end);
        }
        space.break_point = requested;
        space.break_point
    }

    pub(super) fn shmat(&self, registers: &Regs, memory: &GuestMemory) -> u64 {
        const VALID_FLAGS: i32 =
            libc::SHM_RDONLY | libc::SHM_RND | libc::SHM_REMAP | libc::SHM_EXEC;
        let [shmid_raw, shmaddr, shmflg_raw, ..] = registers.arguments();
        let shmid = GuestReg(shmid_raw).as_i32();
        let shmflg = GuestReg(shmflg_raw).as_i32();
        if shmflg & !VALID_FLAGS != 0 || (shmaddr == 0 && shmflg & libc::SHM_REMAP != 0) {
            return Errno::EINVAL.negated();
        }
        let mut ds: libc::shmid_ds = unsafe { std::mem::zeroed() };
        if unsafe { libc::shmctl(shmid, libc::IPC_STAT, &raw mut ds) } < 0 {
            return Errno::last_os(Errno::EINVAL).negated();
        }
        let seg_size = u64::try_from(ds.shm_segsz).unwrap_or(0);
        if seg_size == 0 {
            return Errno::EINVAL.negated();
        }
        let Some(length) = AddressSpace::page_align_len(seg_size) else {
            return Errno::ENOMEM.negated();
        };
        let mut space = self
            .space
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let address = if shmaddr == 0 {
            let Some(addr) = space.find_free_top_down(length, RESERVED_END, MAPPING_CEILING) else {
                return Errno::ENOMEM.negated();
            };
            addr
        } else {
            let addr = if shmflg & libc::SHM_RND != 0 {
                shmaddr & !(PAGE_BYTES - 1)
            } else if shmaddr.is_multiple_of(PAGE_BYTES) {
                shmaddr
            } else {
                return Errno::EINVAL.negated();
            };
            let Some(end) = addr.checked_add(length) else {
                return Errno::EINVAL.negated();
            };
            if addr < RESERVED_END || end > memory.size() {
                return Errno::EINVAL.negated();
            }
            if shmflg & libc::SHM_REMAP == 0 && space.overlaps(addr, end) {
                return Errno::EINVAL.negated();
            }
            addr
        };
        if let Err(errno) = memory.attach_shm(address, length, shmid, shmflg) {
            return errno.negated();
        }
        let mut prot = libc::PROT_READ.cast_unsigned();
        if shmflg & libc::SHM_RDONLY == 0 {
            prot |= libc::PROT_WRITE.cast_unsigned();
        }
        if shmflg & libc::SHM_EXEC != 0 {
            prot |= libc::PROT_EXEC.cast_unsigned();
        }
        if self.machine.protect_pages(address, length, prot).is_err() {
            let _ = memory.detach_shm(address);
            let _ = memory.restore_anonymous(address, length);
            return Errno::ENOMEM.negated();
        }
        space.insert_range(
            address,
            address + length,
            MappingMeta {
                kind: MappingKind::SysvShm { base: address },
                prot,
                shared: true,
                advised: false,
                dont_fork: false,
            },
        );
        address
    }

    pub(super) fn shmdt(&self, registers: &Regs, memory: &GuestMemory) -> u64 {
        let shmaddr = registers.arguments()[0];
        if !shmaddr.is_multiple_of(PAGE_BYTES) {
            return Errno::EINVAL.negated();
        }
        let mut space = self
            .space
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !space.has_shm_base(shmaddr) {
            return Errno::EINVAL.negated();
        }
        if let Err(errno) = memory.detach_shm(shmaddr) {
            return errno.negated();
        }
        for (start, end) in space.take_shm_segments(shmaddr) {
            let length = end - start;
            let _ = memory.restore_anonymous(start, length);
            let _ = self.machine.protect_pages(start, length, 0);
        }
        0
    }

    pub(super) fn mlock_range(
        &self,
        registers: &Regs,
        memory: &GuestMemory,
        syscall: Sysno,
    ) -> u64 {
        const MLOCK_ONFAULT: i32 = 1;
        let [address, size, flags, ..] = registers.arguments();
        if syscall == Sysno::mlock2 && GuestReg(flags).as_i32() & !MLOCK_ONFAULT != 0 {
            return Errno::EINVAL.negated();
        }
        if size == 0 {
            return 0;
        }
        let start = address & !(PAGE_BYTES - 1);
        let offset = address - start;
        let Some(raw_len) = size.checked_add(offset) else {
            return Errno::EINVAL.negated();
        };
        let Some(length) = AddressSpace::page_align_len(raw_len) else {
            return Errno::EINVAL.negated();
        };
        let Some(end) = start.checked_add(length) else {
            return Errno::EINVAL.negated();
        };
        if start < RESERVED_END || end > memory.size() {
            return Errno::ENOMEM.negated();
        }
        let mapped = self
            .space
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_fully_mapped(start, end);
        if !mapped {
            return Errno::ENOMEM.negated();
        }
        let Ok(host_addr) = memory.address(start, length) else {
            return Errno::ENOMEM.negated();
        };
        SyscallArgs::invoke(syscall, &[host_addr, length, flags, 0, 0, 0])
    }

    pub(super) fn mlockall(&self, registers: &Regs) -> u64 {
        const MCL_VALID: i32 = 1 | 2 | 4;
        let flags = GuestReg(registers.arguments()[0]).as_i32();
        if flags == 0 || flags & !MCL_VALID != 0 {
            return Errno::EINVAL.negated();
        }
        // Lock only active guest mappings, never the 64 GiB backing reservation.
        let space = self
            .space
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let lock_flags = u64::from(flags & 4 != 0);
        for (&start, &(end, _)) in &space.regions {
            if start < end
                && let Ok(host_addr) = self.machine.memory.address(start, end - start)
            {
                let rc = SyscallArgs::invoke(
                    Sysno::mlock2,
                    &[host_addr, end - start, lock_flags, 0, 0, 0],
                );
                if GuestReg(rc).as_c_long() < 0 {
                    return rc;
                }
            }
        }
        0
    }

    pub(super) fn mbind(&self, registers: &Regs, memory: &GuestMemory) -> u64 {
        let [start, len, mode, nodemask, maxnode, flags] = registers.arguments();
        let probe = SyscallArgs::invoke(Sysno::mbind, &[0, 0, u64::MAX, 0, 0, u64::MAX]);
        if probe == Errno::ENOSYS.negated() {
            return probe;
        }
        if !start.is_multiple_of(PAGE_BYTES) || maxnode > 65_536 {
            return Errno::EINVAL.negated();
        }
        if len == 0 {
            return 0;
        }
        let Some(aligned) = AddressSpace::page_align_len(len) else {
            return Errno::EINVAL.negated();
        };
        let Some(end) = start.checked_add(aligned) else {
            return Errno::EINVAL.negated();
        };
        let mapped = self
            .space
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_fully_mapped(start, end);
        if !mapped {
            return Errno::EFAULT.negated();
        }
        let Ok(host_start) = memory.address(start, aligned) else {
            return Errno::EINVAL.negated();
        };
        let mask_bytes = maxnode.saturating_sub(1).div_ceil(64) * WORD_SIZE;
        let host_mask = if nodemask == 0 {
            0
        } else {
            memory.translated_address(nodemask, mask_bytes)
        };
        SyscallArgs::invoke(
            Sysno::mbind,
            &[host_start, aligned, mode, host_mask, maxnode, flags],
        )
    }

    pub(super) fn set_mempolicy_home_node(&self, registers: &Regs, memory: &GuestMemory) -> u64 {
        let [start, len, home_node, flags, ..] = registers.arguments();
        let probe = SyscallArgs::invoke(Sysno::set_mempolicy_home_node, &[0, 0, 0, u64::MAX, 0, 0]);
        if probe == Errno::ENOSYS.negated() {
            return probe;
        }
        if flags != 0 || !start.is_multiple_of(PAGE_BYTES) {
            return Errno::EINVAL.negated();
        }
        if len == 0 {
            return 0;
        }
        let Some(aligned) = AddressSpace::page_align_len(len) else {
            return Errno::EINVAL.negated();
        };
        let Some(end) = start.checked_add(aligned) else {
            return Errno::EINVAL.negated();
        };
        let mapped = self
            .space
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_fully_mapped(start, end);
        if !mapped {
            return Errno::ENOMEM.negated();
        }
        let Ok(host_start) = memory.address(start, aligned) else {
            return Errno::EINVAL.negated();
        };
        SyscallArgs::invoke(
            Sysno::set_mempolicy_home_node,
            &[host_start, aligned, home_node, flags, 0, 0],
        )
    }

    pub(super) fn mseal(registers: &Regs) -> u64 {
        let probe = SyscallArgs::invoke(Sysno::mseal, &[0, 0, u64::MAX, 0, 0, 0]);
        if probe == Errno::ENOSYS.negated() {
            return probe;
        }
        let [address, _, flags, ..] = registers.arguments();
        if flags != 0 || !address.is_multiple_of(PAGE_BYTES) {
            return Errno::EINVAL.negated();
        }
        // Sealing host VMAs in `GuestMemory` would prevent `munmap` and `exec`
        // from restoring the backing anonymous reservation.
        Errno::EPERM.negated()
    }

    pub(super) fn remap_file_pages(registers: &Regs) -> u64 {
        let probe = SyscallArgs::invoke(Sysno::remap_file_pages, &[0, 0, u64::MAX, 0, 0, 0]);
        if probe == Errno::ENOSYS.negated() {
            return probe;
        }
        let _ = registers;
        Errno::EINVAL.negated()
    }

    pub(super) fn map_shadow_stack(registers: &Regs) -> u64 {
        let probe = SyscallArgs::invoke(Sysno::map_shadow_stack, &[0, 0, u64::MAX, 0, 0, 0]);
        if probe == Errno::ENOSYS.negated() {
            return probe;
        }
        let [_, _, flags, ..] = registers.arguments();
        if flags & !1 != 0 {
            return probe;
        }
        Errno::EOPNOTSUPP.negated()
    }

    pub(super) fn pkey_free() -> u64 {
        SyscallArgs::invoke(Sysno::pkey_free, &[u64::MAX, 0, 0, 0, 0, 0])
    }

    pub(super) fn pkey_alloc(registers: &Regs) -> u64 {
        let probe = Self::pkey_free();
        if probe == Errno::ENOSYS.negated() {
            return probe;
        }
        let [flags, access_rights, ..] = registers.arguments();
        if flags != 0 || access_rights & !3 != 0 {
            return Errno::EINVAL.negated();
        }
        Errno::ENOSPC.negated()
    }

    pub(super) fn pkey_mprotect(&self, registers: &Regs, memory: &GuestMemory) -> u64 {
        let probe = Self::pkey_free();
        if probe == Errno::ENOSYS.negated() {
            return probe;
        }
        if GuestReg(registers.arguments()[3]).as_i32() == 0 {
            self.mprotect(registers, memory)
        } else {
            Errno::EINVAL.negated()
        }
    }
}
