// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Supplementary groups and output buffers, compared with the host by `compat`.

use super::super::proc::Mapping;
use super::{OsResult, ProbeError, ProbeResult};
use std::io;

fn query(size: u64, address: usize) -> Result<libc::c_long, i32> {
    unsafe { libc::syscall(libc::SYS_getgroups, size, address) }
        .os_result()
        .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))
}

fn identity(groups: &[libc::gid_t]) -> ProbeResult<()> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let listed = status
        .lines()
        .find_map(|line| line.strip_prefix("Groups:"))
        .ok_or_else(|| ProbeError::broken("proc status does not list supplementary groups"))?;
    let listed = listed
        .split_whitespace()
        .map(str::parse::<libc::gid_t>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    let mut maps = Vec::new();
    for line in std::fs::read_to_string("/proc/self/gid_map")?.lines() {
        let fields = line
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(io::Error::other)?;
        let fields: [u32; 3] = fields
            .try_into()
            .map_err(|_| ProbeError::broken("invalid proc gid map"))?;
        maps.push(fields.map(u64::from));
    }
    let overflow = std::fs::read_to_string("/proc/sys/kernel/overflowgid")?
        .trim()
        .parse::<u32>()
        .map(u64::from)
        .map_err(io::Error::other)?;
    if groups.iter().any(|&gid| {
        let gid = u64::from(gid);
        gid != overflow
            && !maps
                .iter()
                .any(|[inside, _, length]| gid >= *inside && gid - *inside < *length)
    }) {
        return Err(ProbeError::broken(
            "getgroups returned a GID outside its namespace map",
        ));
    }
    // A broker-opened proc file renders IDs in the opener's namespace. The
    // seccomp broker is in our parent user namespace; KVM opens the file itself.
    let mapped: Vec<_> = listed
        .iter()
        .map(|&gid| {
            let gid = u64::from(gid);
            maps.iter()
                .find_map(|[inside, parent, length]| {
                    let offset = gid.checked_sub(*parent)?;
                    (offset < *length).then_some(*inside + offset)
                })
                .unwrap_or(overflow)
        })
        .collect();
    if groups != listed.as_slice() && !groups.iter().copied().map(u64::from).eq(mapped) {
        return Err(ProbeError::broken(
            "getgroups differs from namespace-mapped proc status",
        ));
    }
    let inherited = std::thread::spawn(nix::unistd::getgroups)
        .join()
        .map_err(|_| ProbeError::broken("group query thread panicked"))?
        .map_err(io::Error::from)?;
    if !inherited
        .iter()
        .map(|group| group.as_raw())
        .eq(groups.iter().copied())
    {
        return Err(ProbeError::broken(
            "thread did not inherit supplementary groups",
        ));
    }
    Ok(())
}

pub(super) fn run() -> ProbeResult<Vec<u8>> {
    let groups = nix::unistd::getgroups().map_err(io::Error::from)?;
    let groups: Vec<_> = groups.into_iter().map(nix::unistd::Gid::as_raw).collect();
    let count = u32::try_from(groups.len()).map_err(io::Error::other)?;
    identity(&groups)?;
    let mut buffer = vec![libc::gid_t::MAX; groups.len() + 2];
    let address = unsafe { buffer.as_mut_ptr().add(1) }.addr();
    for size in [
        u64::from(count),
        u64::from(count) + 1,
        u64::from(i32::MAX.cast_unsigned()),
        (1u64 << 32) | u64::from(count),
    ] {
        buffer.fill(libc::gid_t::MAX);
        let result = query(size, address);
        if result != Ok(i64::from(count))
            || buffer[1..=groups.len()] != groups
            || buffer[0] != libc::gid_t::MAX
            || buffer[groups.len() + 1] != libc::gid_t::MAX
        {
            return Err(ProbeError::broken(
                "getgroups wrote outside its actual group list",
            ));
        }
    }
    buffer.fill(libc::gid_t::MAX);
    for size in [0, 1u64 << 32] {
        for address in [0, 1, usize::MAX, address] {
            if query(size, address) != Ok(i64::from(count)) {
                return Err(ProbeError::broken(
                    "zero-size group query accessed its output buffer",
                ));
            }
        }
    }
    if buffer.iter().any(|&group| group != libc::gid_t::MAX) {
        return Err(ProbeError::broken(
            "zero-size group query modified its buffer",
        ));
    }

    let mut errors = Vec::new();
    for size in [1, u64::from(count.saturating_sub(1))] {
        errors.push(query(size, address));
        if size > 0
            && size < u64::from(count)
            && buffer.iter().any(|&group| group != libc::gid_t::MAX)
        {
            return Err(ProbeError::broken("short group buffer was modified"));
        }
    }
    for size in [u64::MAX, 1u64 << 31, u64::from(u32::MAX)] {
        errors.push(query(size, address));
        errors.push(query(size, usize::MAX));
    }

    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.os_result()?)
        .map_err(io::Error::other)?;
    let pages = Mapping::new(2 * page, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1)?;
    unsafe { libc::mprotect(pages.ptr.byte_add(page), page, libc::PROT_NONE) }.os_result()?;
    for address in [0, 1, usize::MAX, pages.ptr.addr() + page] {
        errors.push(query(u64::from(count).max(1), address));
    }
    let width = std::mem::size_of::<libc::gid_t>();
    let prefix = groups.len().min(page / width).saturating_sub(1);
    let partial = unsafe {
        pages
            .ptr
            .byte_add(page - prefix * width)
            .cast::<libc::gid_t>()
    };
    let partial_result = query(u64::from(count).max(1), partial.addr());
    let written = unsafe { std::slice::from_raw_parts(partial, prefix) };
    if written != &groups[..prefix] {
        return Err(ProbeError::broken(
            "group query did not retain writes before a fault",
        ));
    }
    errors.push(partial_result);
    unsafe { libc::mprotect(pages.ptr, page, libc::PROT_READ) }.os_result()?;
    errors.push(query(u64::from(count).max(1), pages.ptr.addr()));
    Ok(format!("{count} groups; namespace and thread IDs consistent; bounded writes; query errors {errors:?}").into_bytes())
}
