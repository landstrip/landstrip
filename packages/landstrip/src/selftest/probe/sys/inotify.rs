// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::super::proc::Mapping;
use super::{CPath, OsResult, Probe, ProbeError, ProbeResult, SysCheck, SysProbe};
use nix::sys::inotify::{InitFlags, Inotify};
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::symlink;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

struct Watcher(Inotify);

#[derive(Debug)]
struct Event {
    watch: i32,
    mask: u32,
    cookie: u32,
    name: Vec<u8>,
}

impl Watcher {
    fn new(flags: i32) -> ProbeResult<Self> {
        let flags = InitFlags::from_bits_retain(flags);
        Ok(Self(Inotify::init(flags).map_err(io::Error::from)?))
    }

    fn fd(&self) -> i32 {
        self.0.as_fd().as_raw_fd()
    }

    fn add(&self, path: &Path, mask: u32) -> ProbeResult<i32> {
        let path = path.c_path()?;
        Ok(unsafe { libc::inotify_add_watch(self.fd(), path.as_ptr(), mask) }.os_result()?)
    }

    fn remove(&self, watch: i32) -> ProbeResult<()> {
        unsafe { libc::inotify_rm_watch(self.fd(), watch) }.os_result()?;
        Ok(())
    }

    fn events(&mut self) -> ProbeResult<Vec<Event>> {
        let mut poll = libc::pollfd {
            fd: self.fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&raw mut poll, 1, 2000) }.os_result()? != 1
            || poll.revents != libc::POLLIN
        {
            return Err(ProbeError::broken("inotify did not become readable"));
        }
        let events = self.0.read_events().map_err(io::Error::from)?;
        if events.is_empty() {
            return Err(ProbeError::broken("empty inotify read"));
        }
        Ok(events
            .into_iter()
            .map(|event| Event {
                watch: event.wd.as_raw(),
                mask: event.mask.bits(),
                cookie: event.cookie,
                name: event.name.map_or_else(Vec::new, OsStringExt::into_vec),
            })
            .collect())
    }

    fn expect(&mut self, expected: &[(i32, u32, &[u8])]) -> ProbeResult<()> {
        let mut events = self.events()?;
        // IN_IGNORED can arrive in a later read than IN_DELETE_SELF.
        while events.len() < expected.len() {
            events.extend(self.events()?);
        }
        if events.len() != expected.len()
            || events
                .iter()
                .zip(expected)
                .any(|(event, &(watch, mask, name))| {
                    event.watch != watch || event.mask != mask || event.name != name
                })
        {
            return Err(ProbeError::broken(&format!(
                "inotify events {events:?} differ from {expected:?}"
            )));
        }
        Ok(())
    }

    fn empty(&mut self) -> ProbeResult<()> {
        match self.0.read_events() {
            Err(nix::errno::Errno::EAGAIN) => Ok(()),
            Err(error) => Err(io::Error::from(error).into()),
            Ok(_) => Err(ProbeError::broken(
                "an empty nonblocking inotify read did not return EAGAIN",
            )),
        }
    }
}

pub(super) fn run(check: SysCheck, dir: &Path) -> ProbeResult<Vec<u8>> {
    let root = dir.join(check.to_string());
    fs::create_dir(&root)?;
    match check {
        SysCheck::InotifyEvents => events(&root)?,
        SysCheck::InotifyWatches => watches(&root)?,
        SysCheck::InotifyPaths => paths(&root)?,
        SysCheck::InotifyIo => io(&root)?,
        SysCheck::InotifyErrors => errors(&root)?,
        SysCheck::InotifyFork => fork(&root)?,
        SysCheck::InotifyExec => return exec(&root),
        _ => return Err(ProbeError::broken("not an inotify check")),
    }
    fs::remove_dir_all(&root)?;
    Ok(b"watch state preserved".to_vec())
}

fn events(dir: &Path) -> ProbeResult<()> {
    let mut watcher = Watcher::new(libc::IN_CLOEXEC)?;
    let watch = watcher.add(
        dir,
        libc::IN_CREATE | libc::IN_MODIFY | libc::IN_CLOSE_WRITE,
    )?;
    fs::write(dir.join("before"), b"data")?;
    watcher.expect(&[
        (watch, libc::IN_CREATE, b"before"),
        (watch, libc::IN_MODIFY, b"before"),
        (watch, libc::IN_CLOSE_WRITE, b"before"),
    ])?;
    if watcher.add(dir, libc::IN_MOVED_FROM | libc::IN_MOVED_TO)? != watch {
        return Err(ProbeError::broken(
            "replacing a watch changed its descriptor",
        ));
    }
    fs::rename(dir.join("before"), dir.join("after"))?;
    let events = watcher.events()?;
    if events.len() != 2
        || events[0].watch != watch
        || events[0].mask != libc::IN_MOVED_FROM
        || events[0].name != b"before"
        || events[1].watch != watch
        || events[1].mask != libc::IN_MOVED_TO
        || events[1].name != b"after"
        || events[0].cookie == 0
        || events[0].cookie != events[1].cookie
    {
        return Err(ProbeError::broken(
            "rename events lost their names or paired cookie",
        ));
    }
    Ok(())
}

fn watches(dir: &Path) -> ProbeResult<()> {
    let mut watcher = Watcher::new(libc::IN_CLOEXEC | libc::IN_NONBLOCK)?;
    let watch = watcher.add(dir, libc::IN_CREATE)?;
    if watcher.add(dir, libc::IN_DELETE)? != watch {
        return Err(ProbeError::broken(
            "watch mask replacement allocated another watch",
        ));
    }
    let entry = dir.join("entry");
    fs::write(&entry, b"")?;
    watcher.empty()?;
    fs::remove_file(&entry)?;
    watcher.expect(&[(watch, libc::IN_DELETE, b"entry")])?;
    if watcher.add(dir, libc::IN_MASK_ADD | libc::IN_CREATE)? != watch {
        return Err(ProbeError::broken(
            "adding a watch mask allocated another watch",
        ));
    }
    fs::write(&entry, b"")?;
    fs::remove_file(&entry)?;
    watcher.expect(&[
        (watch, libc::IN_CREATE, b"entry"),
        (watch, libc::IN_DELETE, b"entry"),
    ])?;
    watcher.remove(watch)?;
    watcher.expect(&[(watch, libc::IN_IGNORED, b"")])?;
    fs::write(&entry, b"")?;
    watcher.empty()?;
    let once = watcher.add(dir, libc::IN_CREATE | libc::IN_ONESHOT)?;
    fs::write(dir.join("once"), b"")?;
    fs::write(dir.join("twice"), b"")?;
    watcher.expect(&[
        (once, libc::IN_CREATE, b"once"),
        (once, libc::IN_IGNORED, b""),
    ])?;
    watcher.empty()
}

fn paths(dir: &Path) -> ProbeResult<()> {
    use std::os::unix::ffi::OsStrExt;

    let target = dir.join("target");
    let link = dir.join("link");
    fs::create_dir(&target)?;
    symlink(&target, &link)?;
    let mut watcher = Watcher::new(libc::IN_CLOEXEC)?;
    let cpath = link.c_path()?;
    expect_errno(
        unsafe {
            libc::inotify_add_watch(
                watcher.fd(),
                cpath.as_ptr(),
                libc::IN_CREATE | libc::IN_ONLYDIR | libc::IN_DONT_FOLLOW,
            )
        }
        .into(),
        libc::ENOTDIR,
    )?;
    let followed = watcher.add(&link, libc::IN_CREATE | libc::IN_ONLYDIR)?;
    let symlink_watch = watcher.add(&link, libc::IN_DELETE_SELF | libc::IN_DONT_FOLLOW)?;
    if followed == symlink_watch {
        return Err(ProbeError::broken(
            "IN_DONT_FOLLOW watched the symlink target",
        ));
    }
    fs::write(target.join(std::ffi::OsStr::from_bytes(b"raw-\xff")), b"")?;
    watcher.expect(&[(followed, libc::IN_CREATE, b"raw-\xff")])?;
    fs::remove_file(&link)?;
    watcher.expect(&[
        (symlink_watch, libc::IN_DELETE_SELF, b""),
        (symlink_watch, libc::IN_IGNORED, b""),
    ])?;
    std::env::set_current_dir(dir)?;
    let relative = watcher.add(Path::new("."), libc::IN_CREATE)?;
    fs::write("relative", b"")?;
    watcher.expect(&[(relative, libc::IN_CREATE, b"relative")])?;
    std::env::set_current_dir(
        dir.parent()
            .ok_or_else(|| ProbeError::broken("watch root has no parent"))?,
    )?;
    Ok(())
}

fn io(dir: &Path) -> ProbeResult<()> {
    let mut watcher = Watcher::new(libc::IN_CLOEXEC | libc::IN_NONBLOCK)?;
    watcher.empty()?;
    let flags = unsafe { libc::fcntl(watcher.fd(), libc::F_GETFL) }.os_result()?;
    let descriptor_flags = unsafe { libc::fcntl(watcher.fd(), libc::F_GETFD) }.os_result()?;
    if flags & libc::O_NONBLOCK == 0 || descriptor_flags & libc::FD_CLOEXEC == 0 {
        return Err(ProbeError::broken("inotify_init1 lost descriptor flags"));
    }
    let watch = watcher.add(dir, libc::IN_CREATE)?;
    let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) }.os_result()?;
    let epoll = unsafe { File::from_raw_fd(fd) };
    let mut event = libc::epoll_event {
        events: libc::EPOLLIN.cast_unsigned(),
        u64: 42,
    };
    unsafe {
        libc::epoll_ctl(
            epoll.as_raw_fd(),
            libc::EPOLL_CTL_ADD,
            watcher.fd(),
            &raw mut event,
        )
    }
    .os_result()?;
    fs::write(dir.join("readable"), b"")?;
    if unsafe { libc::epoll_wait(epoll.as_raw_fd(), &raw mut event, 1, 2000) }.os_result()? != 1
        || event.events != libc::EPOLLIN.cast_unsigned()
        || event.u64 != 42
    {
        return Err(ProbeError::broken("inotify epoll readiness was lost"));
    }
    let mut available: libc::c_int = 0;
    unsafe { libc::ioctl(watcher.fd(), libc::FIONREAD, &raw mut available) }.os_result()?;
    if available <= i32::try_from(size_of::<libc::inotify_event>()).map_err(io::Error::other)? {
        return Err(ProbeError::broken(
            "FIONREAD did not count the inotify event",
        ));
    }
    let mut short = [0_u8; 1];
    expect_errno(
        unsafe {
            libc::syscall(
                libc::SYS_read,
                watcher.fd(),
                short.as_mut_ptr(),
                short.len(),
            )
        },
        libc::EINVAL,
    )?;
    watcher.expect(&[(watch, libc::IN_CREATE, b"readable")])?;
    watcher.empty()
}

fn expect_errno(result: libc::c_long, expected: i32) -> ProbeResult<()> {
    let error = std::io::Error::last_os_error();
    if result != -1 || error.raw_os_error() != Some(expected) {
        return Err(ProbeError::broken(&format!(
            "inotify result {result}, error {error}; expected errno {expected}"
        )));
    }
    Ok(())
}

fn errors(dir: &Path) -> ProbeResult<()> {
    expect_errno(unsafe { libc::inotify_init1(1) }.into(), libc::EINVAL)?;
    #[cfg(target_arch = "x86_64")]
    {
        let fd = unsafe { libc::syscall(libc::SYS_inotify_init) }.os_result()?;
        let file = unsafe { File::from_raw_fd(i32::try_from(fd).map_err(io::Error::other)?) };
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) }.os_result()? != 0
            || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) }.os_result()?
                & libc::O_NONBLOCK
                != 0
        {
            return Err(ProbeError::broken(
                "legacy inotify_init set unexpected flags",
            ));
        }
    }
    let watcher = Watcher::new(libc::IN_CLOEXEC)?;
    let path = dir.c_path()?;
    let fd = watcher.fd();
    expect_errno(
        unsafe { libc::inotify_add_watch(-1, path.as_ptr(), libc::IN_CREATE) }.into(),
        libc::EBADF,
    )?;
    expect_errno(unsafe { libc::inotify_rm_watch(-1, 1) }.into(), libc::EBADF)?;
    let ordinary = File::open(dir)?;
    expect_errno(
        unsafe { libc::inotify_add_watch(ordinary.as_raw_fd(), path.as_ptr(), libc::IN_CREATE) }
            .into(),
        libc::EINVAL,
    )?;
    expect_errno(
        unsafe { libc::inotify_rm_watch(ordinary.as_raw_fd(), 1) }.into(),
        libc::EINVAL,
    )?;
    expect_errno(
        unsafe { libc::inotify_add_watch(fd, std::ptr::null(), libc::IN_CREATE) }.into(),
        libc::EFAULT,
    )?;
    expect_errno(
        unsafe { libc::inotify_add_watch(fd, std::ptr::without_provenance(1), libc::IN_CREATE) }
            .into(),
        libc::EFAULT,
    )?;
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.os_result()?)
        .map_err(io::Error::other)?;
    let pages = Mapping::new(2 * page, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1)?;
    unsafe { libc::mprotect(pages.ptr.byte_add(page), page, libc::PROT_NONE) }.os_result()?;
    let tail = unsafe { pages.ptr.byte_add(page - 6).cast::<u8>() };
    unsafe { std::ptr::copy_nonoverlapping(b"abcdef".as_ptr(), tail, 6) };
    expect_errno(
        unsafe { libc::inotify_add_watch(fd, tail.cast(), libc::IN_CREATE) }.into(),
        libc::EFAULT,
    )?;
    expect_errno(
        unsafe { libc::inotify_add_watch(fd, path.as_ptr(), 0) }.into(),
        libc::EINVAL,
    )?;
    expect_errno(
        unsafe {
            libc::inotify_add_watch(
                fd,
                path.as_ptr(),
                libc::IN_CREATE | libc::IN_MASK_ADD | libc::IN_MASK_CREATE,
            )
        }
        .into(),
        libc::EINVAL,
    )?;
    let missing = dir.join("missing").c_path()?;
    expect_errno(
        unsafe { libc::inotify_add_watch(fd, missing.as_ptr(), libc::IN_CREATE) }.into(),
        libc::ENOENT,
    )?;
    watcher.add(dir, libc::IN_CREATE)?;
    expect_errno(
        unsafe {
            libc::inotify_add_watch(fd, path.as_ptr(), libc::IN_CREATE | libc::IN_MASK_CREATE)
        }
        .into(),
        libc::EEXIST,
    )?;
    expect_errno(
        unsafe { libc::inotify_rm_watch(fd, -1) }.into(),
        libc::EINVAL,
    )?;
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) }.os_result()?;
    let hidden = i32::try_from(limit.rlim_cur).map_err(io::Error::other)?;
    expect_errno(
        unsafe { libc::inotify_add_watch(hidden, path.as_ptr(), libc::IN_CREATE) }.into(),
        libc::EBADF,
    )?;
    expect_errno(
        unsafe { libc::inotify_rm_watch(hidden, 1) }.into(),
        libc::EBADF,
    )
}

fn fork(dir: &Path) -> ProbeResult<()> {
    let mut watcher = Watcher::new(libc::IN_CLOEXEC)?;
    let original = watcher.add(dir, libc::IN_CREATE)?;
    let child = unsafe { libc::fork() }.os_result()?;
    if child == 0 {
        let result = (|| -> ProbeResult<()> {
            watcher.remove(original)?;
            watcher.add(dir, libc::IN_CREATE)?;
            fs::write(dir.join("forked"), b"")?;
            Ok(())
        })();
        unsafe { libc::_exit(i32::from(result.is_err())) }
    }
    let mut status = 0;
    unsafe { libc::waitpid(child, &raw mut status, 0) }.os_result()?;
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err(ProbeError::broken(
            "child could not modify the inherited inotify watch",
        ));
    }
    let events = watcher.events()?;
    if events.len() != 2
        || events[0].watch != original
        || events[0].mask != libc::IN_IGNORED
        || events[1].watch == original
        || events[1].mask != libc::IN_CREATE
        || events[1].name != b"forked"
    {
        return Err(ProbeError::broken(
            "inotify watch state was not shared across fork",
        ));
    }
    watcher.remove(events[1].watch)?;
    watcher.expect(&[(events[1].watch, libc::IN_IGNORED, b"")])
}

fn exec(dir: &Path) -> ProbeResult<Vec<u8>> {
    let watcher = Watcher::new(0)?;
    let closed = Watcher::new(libc::IN_CLOEXEC)?;
    let watch = watcher.add(dir, libc::IN_CREATE)?;
    closed.add(dir, libc::IN_CREATE)?;
    let probe = Probe::from(SysProbe::AfterInotifyExec {
        keep: watcher.fd(),
        closed: closed.fd(),
        watch,
        dir: dir.to_path_buf(),
    });
    Err(Command::new(SysProbe::SELF_EXE)
        .args(
            probe
                .argv()
                .map_err(|error| ProbeError::broken(&error.to_string()))?,
        )
        .exec()
        .into())
}

pub(super) fn after_exec(keep: i32, closed: i32, watch: i32, dir: &Path) -> ProbeResult<Vec<u8>> {
    unsafe { libc::fcntl(keep, libc::F_GETFD) }.os_result()?;
    let label = fs::read_link(Path::new("/proc/self/fd").join(keep.to_string()))?;
    if label != Path::new("anon_inode:inotify") {
        return Err(ProbeError::broken(
            "exec probe did not inherit an inotify descriptor",
        ));
    }
    expect_errno(
        unsafe { libc::fcntl(closed, libc::F_GETFD) }.into(),
        libc::EBADF,
    )?;
    let mut watcher = Watcher(unsafe { Inotify::from_raw_fd(keep) });
    fs::write(dir.join("after-exec"), b"")?;
    watcher.expect(&[(watch, libc::IN_CREATE, b"after-exec")])?;
    watcher.remove(watch)?;
    watcher.expect(&[(watch, libc::IN_IGNORED, b"")])?;
    fs::remove_dir_all(dir)?;
    Ok(b"inotify descriptor and watch survive exec".to_vec())
}
