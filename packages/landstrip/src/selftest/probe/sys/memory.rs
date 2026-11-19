// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Memory mapping and advice behaviour, compared with the host by `compat`.

use super::super::proc::Mapping;
use super::{OsResult, Probe, ProbeError, ProbeResult, SysProbe};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

const PAGE: usize = 4096;

pub(super) fn heap() -> ProbeResult<Vec<u8>> {
    // Avoid allocation between growing and restoring the break: libc's allocator
    // owns the original heap, and must not observe our temporary extension.
    let original = unsafe { libc::syscall(libc::SYS_brk, 0) }.os_result()?;
    let start = original.cast_unsigned().next_multiple_of(PAGE as u64);
    let end = start + 3 * PAGE as u64;
    if unsafe { libc::syscall(libc::SYS_brk, end) }.cast_unsigned() != end {
        return Err(ProbeError::broken(
            "could not extend heap for mapping probe",
        ));
    }
    let mapped = unsafe { libc::msync(start as *mut libc::c_void, 3 * PAGE, libc::MS_SYNC) };
    let unmapped = unsafe { libc::munmap((start + PAGE as u64) as *mut libc::c_void, PAGE) };
    let hole = unsafe { libc::msync(start as *mut libc::c_void, 3 * PAGE, libc::MS_SYNC) };
    let hole_errno = std::io::Error::last_os_error().raw_os_error();
    let tail = unsafe {
        libc::msync(
            (start + 2 * PAGE as u64) as *mut libc::c_void,
            PAGE,
            libc::MS_SYNC,
        )
    };
    let restored = unsafe { libc::syscall(libc::SYS_brk, original) };
    if restored != original
        || mapped != 0
        || unmapped != 0
        || hole != -1
        || hole_errno != Some(libc::ENOMEM)
        || tail != 0
    {
        return Err(ProbeError::broken(
            "heap mapping did not retain the munmap hole",
        ));
    }
    Ok(b"heap grows, munmap leaves a hole, tail survives, break restored".to_vec())
}

fn errno(result: i32) -> i32 {
    if result == 0 {
        0
    } else {
        io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO)
    }
}

pub(super) fn ranges() -> ProbeResult<Vec<u8>> {
    let pages = Mapping::new(3 * PAGE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1)?;
    let ptr = pages.ptr.cast::<u8>();
    let mut errors = Vec::new();
    for (address, size, advice) in [
        (0, 0, libc::MADV_NORMAL),
        (1, 0, libc::MADV_NORMAL),
        (0, PAGE, libc::MADV_DONTNEED),
        (ptr.addr(), 0, -1),
        (ptr.addr() + 1, PAGE, libc::MADV_DONTNEED),
        (ptr.addr(), usize::MAX, libc::MADV_NORMAL),
        (usize::MAX & !(PAGE - 1), PAGE, libc::MADV_NORMAL),
    ] {
        errors.push(errno(unsafe {
            libc::madvise(address as *mut libc::c_void, size, advice)
        }));
    }
    unsafe {
        ptr.write_volatile(0xab);
        ptr.add(2 * PAGE).write_volatile(0xcd);
        libc::munmap(ptr.add(PAGE).cast(), PAGE)
    }
    .os_result()?;
    errors.push(errno(unsafe {
        libc::madvise(pages.ptr, 3 * PAGE, libc::MADV_DONTNEED)
    }));
    if unsafe { ptr.read_volatile() != 0 || ptr.add(2 * PAGE).read_volatile() != 0 } {
        return Err(ProbeError::broken(
            "advice must apply on both sides of an unmapped hole",
        ));
    }
    unsafe { libc::mprotect(pages.ptr, PAGE, libc::PROT_NONE) }.os_result()?;
    let advised = unsafe { libc::madvise(pages.ptr, PAGE, libc::MADV_DONTNEED) }.os_result();
    unsafe { libc::mprotect(pages.ptr, PAGE, libc::PROT_READ | libc::PROT_WRITE) }.os_result()?;
    advised?;
    for prot in [libc::PROT_NONE, libc::PROT_READ, libc::PROT_EXEC] {
        unsafe { libc::mprotect(pages.ptr, PAGE, prot) }.os_result()?;
        for advice in [libc::MADV_POPULATE_READ, libc::MADV_POPULATE_WRITE] {
            errors.push(errno(unsafe { libc::madvise(pages.ptr, PAGE, advice) }));
        }
    }
    unsafe { libc::mprotect(pages.ptr, PAGE, libc::PROT_READ | libc::PROT_WRITE) }.os_result()?;
    Ok(format!("range errors {errors:?}; partial discard and PROT_NONE supported").into_bytes())
}

pub(super) fn files(dir: &Path) -> ProbeResult<Vec<u8>> {
    let path = dir.join("advice-data");
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)?;
    std::fs::remove_file(path)?;
    file.write_all(&vec![0x11; PAGE])?;
    let private = Mapping::new(PAGE, libc::MAP_PRIVATE, file.as_raw_fd())?;
    unsafe { private.ptr.cast::<u8>().write_volatile(0x22) };
    file.write_all_at(&[0x33], 0)?;
    unsafe { libc::madvise(private.ptr, PAGE, libc::MADV_DONTNEED) }.os_result()?;
    if unsafe { private.ptr.cast::<u8>().read_volatile() } != 0x33 {
        return Err(ProbeError::broken(
            "private file mapping did not refault current file data",
        ));
    }
    let shared = Mapping::new(PAGE, libc::MAP_SHARED, file.as_raw_fd())?;
    unsafe { shared.ptr.cast::<u8>().write_volatile(0x44) };
    unsafe { libc::madvise(shared.ptr, PAGE, libc::MADV_DONTNEED) }.os_result()?;
    let mut byte = [0];
    file.read_exact_at(&mut byte, 0)?;
    if byte != [0x44] || unsafe { shared.ptr.cast::<u8>().read_volatile() } != 0x44 {
        return Err(ProbeError::broken("discard erased shared file data"));
    }
    unsafe { libc::madvise(shared.ptr, PAGE, libc::MADV_REMOVE) }.os_result()?;
    file.read_exact_at(&mut byte, 0)?;
    if byte != [0] || unsafe { shared.ptr.cast::<u8>().read_volatile() } != 0 {
        return Err(ProbeError::broken(
            "MADV_REMOVE did not punch a hole in the file",
        ));
    }
    let anonymous = Mapping::new(PAGE, libc::MAP_SHARED | libc::MAP_ANONYMOUS, -1)?;
    unsafe { anonymous.ptr.cast::<u8>().write_volatile(0x55) };
    unsafe { libc::madvise(anonymous.ptr, PAGE, libc::MADV_DONTNEED) }.os_result()?;
    if unsafe { anonymous.ptr.cast::<u8>().read_volatile() } != 0x55 {
        return Err(ProbeError::broken("discard erased shared anonymous data"));
    }
    let free = errno(unsafe { libc::madvise(shared.ptr, PAGE, libc::MADV_FREE) });
    let wipe = errno(unsafe { libc::madvise(shared.ptr, PAGE, libc::MADV_WIPEONFORK) });
    Ok(
        format!("file refault, shared data, hole punch; invalid shared advice {free}/{wipe}")
            .into_bytes(),
    )
}

fn child(check: impl FnOnce() -> bool) -> ProbeResult<()> {
    let pid = unsafe { libc::fork() }.os_result()?;
    if pid == 0 {
        unsafe { libc::_exit(i32::from(!check())) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &raw mut status, 0) }.os_result()?;
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err(ProbeError::broken(&format!(
            "advised child failed: wait status {status}"
        )));
    }
    Ok(())
}

extern "C" fn expected_fault(_: i32) {
    unsafe { libc::_exit(0) };
}

pub(super) fn fork() -> ProbeResult<Vec<u8>> {
    let pages = Mapping::new(4 * PAGE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1)?;
    let ptr = pages.ptr.cast::<u8>();
    for (index, advice) in [
        libc::MADV_DONTFORK,
        libc::MADV_DONTFORK,
        libc::MADV_WIPEONFORK,
        libc::MADV_WIPEONFORK,
    ]
    .into_iter()
    .enumerate()
    {
        unsafe { ptr.add(index * PAGE).write_volatile(0xab) };
        unsafe { libc::madvise(ptr.add(index * PAGE).cast(), PAGE, advice) }.os_result()?;
    }
    unsafe { libc::madvise(ptr.add(PAGE).cast(), PAGE, libc::MADV_DOFORK) }.os_result()?;
    unsafe { libc::madvise(ptr.add(3 * PAGE).cast(), PAGE, libc::MADV_KEEPONFORK) }.os_result()?;
    child(|| unsafe {
        let omitted = libc::msync(pages.ptr, PAGE, libc::MS_SYNC) == -1
            && io::Error::last_os_error().raw_os_error() == Some(libc::ENOMEM);
        let values = ptr.add(PAGE).read_volatile() == 0xab
            && ptr.add(2 * PAGE).read_volatile() == 0
            && ptr.add(3 * PAGE).read_volatile() == 0xab;
        let replaced = libc::mmap(
            pages.ptr,
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        );
        omitted && values && replaced == pages.ptr
    })?;
    child(|| unsafe {
        if libc::signal(libc::SIGSEGV, expected_fault as *const () as usize) == libc::SIG_ERR {
            return false;
        }
        ptr.read_volatile();
        false
    })?;
    if unsafe { ptr.read_volatile() != 0xab || ptr.add(2 * PAGE).read_volatile() != 0xab } {
        return Err(ProbeError::broken("child advice changed parent data"));
    }
    Ok(
        b"DONTFORK faults and permits replacement; DOFORK, WIPEONFORK and KEEPONFORK preserved"
            .to_vec(),
    )
}

pub(super) fn reuse() -> ProbeResult<Vec<u8>> {
    let pages = Mapping::new(3 * PAGE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1)?;
    let ptr = pages.ptr.cast::<u8>();
    unsafe { libc::madvise(pages.ptr, 3 * PAGE, libc::MADV_DONTFORK) }.os_result()?;
    let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED;
    if unsafe {
        libc::mmap(
            pages.ptr,
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            flags,
            -1,
            0,
        )
    } == libc::MAP_FAILED
    {
        return Err(io::Error::last_os_error().into());
    }
    unsafe { libc::munmap(ptr.add(PAGE).cast(), PAGE) }.os_result()?;
    if unsafe {
        libc::mmap(
            ptr.add(PAGE).cast(),
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            flags | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    } == libc::MAP_FAILED
    {
        return Err(io::Error::last_os_error().into());
    }
    child(|| unsafe {
        libc::msync(pages.ptr, 2 * PAGE, libc::MS_SYNC) == 0
            && libc::msync(ptr.add(2 * PAGE).cast(), PAGE, libc::MS_SYNC) == -1
            && io::Error::last_os_error().raw_os_error() == Some(libc::ENOMEM)
    })?;
    Ok(b"replacement and unmap reset advice; untouched neighbour retains it".to_vec())
}

pub(super) fn remap() -> ProbeResult<Vec<u8>> {
    let source = Mapping::new(4 * PAGE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1)?;
    let ptr = source.ptr.cast::<u8>();
    unsafe { libc::munmap(ptr.add(3 * PAGE).cast(), PAGE) }.os_result()?;
    unsafe { libc::madvise(source.ptr, PAGE, libc::MADV_RANDOM) }.os_result()?;
    unsafe { libc::madvise(source.ptr, PAGE, libc::MADV_NORMAL) }.os_result()?;
    if unsafe { libc::mremap(source.ptr, 3 * PAGE, 4 * PAGE, 0) } != source.ptr {
        return Err(ProbeError::broken(
            "restored advice prevented remapping merged VMAs",
        ));
    }
    unsafe { libc::munmap(ptr.add(PAGE).cast(), 3 * PAGE) }.os_result()?;
    unsafe { libc::madvise(source.ptr, PAGE, libc::MADV_WIPEONFORK) }.os_result()?;
    if unsafe { libc::mremap(source.ptr, PAGE, 2 * PAGE, 0) } != source.ptr {
        return Err(ProbeError::broken(
            "could not grow advised mapping in place",
        ));
    }
    unsafe {
        ptr.write_volatile(0xab);
        ptr.add(PAGE).write_volatile(0xcd);
    }
    child(|| unsafe { ptr.read_volatile() == 0 && ptr.add(PAGE).read_volatile() == 0 })?;
    let target = Mapping::new(3 * PAGE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1)?;
    if unsafe {
        libc::mremap(
            source.ptr,
            2 * PAGE,
            2 * PAGE,
            libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED,
            target.ptr,
        )
    } != target.ptr
    {
        return Err(io::Error::last_os_error().into());
    }
    let moved = target.ptr.cast::<u8>();
    if unsafe { moved.read_volatile() != 0xab || moved.add(PAGE).read_volatile() != 0xcd } {
        return Err(ProbeError::broken("remap lost advised parent data"));
    }
    child(|| unsafe { moved.read_volatile() == 0 && moved.add(PAGE).read_volatile() == 0 })?;
    Ok(b"in-place growth and fixed relocation preserve fork advice and parent data".to_vec())
}

pub(super) fn hints() -> ProbeResult<Vec<u8>> {
    let page = Mapping::new(PAGE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1)?;
    let mut errors = Vec::new();
    for advice in [
        libc::MADV_NORMAL,
        libc::MADV_RANDOM,
        libc::MADV_SEQUENTIAL,
        libc::MADV_WILLNEED,
        libc::MADV_FREE,
        libc::MADV_DONTDUMP,
        libc::MADV_DODUMP,
        libc::MADV_MERGEABLE,
        libc::MADV_UNMERGEABLE,
        libc::MADV_HUGEPAGE,
        libc::MADV_NOHUGEPAGE,
        libc::MADV_COLD,
        libc::MADV_PAGEOUT,
        libc::MADV_POPULATE_READ,
        libc::MADV_POPULATE_WRITE,
    ] {
        errors.push(errno(unsafe { libc::madvise(page.ptr, PAGE, advice) }));
    }
    unsafe { page.ptr.cast::<u8>().write_volatile(0xab) };
    if unsafe { page.ptr.cast::<u8>().read_volatile() } != 0xab {
        return Err(ProbeError::broken("advice lost a subsequent write"));
    }
    Ok(format!("host-supported advice {errors:?}; subsequent write retained").into_bytes())
}

fn exec_page() -> io::Result<Mapping> {
    // A fixed, otherwise unused address lets the next image test the same host
    // VMA without depending on native ASLR or KVM's allocation order.
    Mapping::at(
        0x1_0000_0000,
        PAGE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
        -1,
    )
}

pub(super) fn exec() -> ProbeResult<Vec<u8>> {
    let page = exec_page()?;
    unsafe { libc::madvise(page.ptr, PAGE, libc::MADV_DONTFORK) }.os_result()?;
    let args = Probe::from(SysProbe::AfterAdviceExec)
        .argv()
        .map_err(|_| ProbeError::broken("cannot encode advice exec probe"))?;
    Err(Command::new(SysProbe::SELF_EXE).args(args).exec().into())
}

pub(super) fn after_exec() -> ProbeResult<Vec<u8>> {
    let page = exec_page()?;
    child(|| unsafe { libc::msync(page.ptr, PAGE, libc::MS_SYNC) == 0 })?;
    Ok(b"exec clears old mapping advice before address reuse".to_vec())
}
