//! Process introspection and identity: cwd probe, signals, exit status
//! mapping, and the shell/home/user resolution from `docs/04-sessions.md`
//! "Shell and home resolution".

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use rustix::process::Pid;

/// Current working directory of `pid`.
///
/// Linux/Android: `readlink("/proc/<pid>/cwd")` (may be denied across uids
/// under `SELinux`). macOS: `proc_pidinfo(PROC_PIDVNODEPATHINFO)`. FreeBSD:
/// `sysctl(kern.proc.cwd.<pid>)` returning one `kinfo_file`. OpenBSD:
/// `sysctl(kern.proc_cwd.<pid>)` returning a NUL-terminated path. NetBSD:
/// `Unsupported` (its `kern.proc_args.<pid>.cwd` sub-op is not exposed by
/// the libc crate).
pub fn process_cwd(pid: u32) -> io::Result<PathBuf> {
    imp::process_cwd(pid)
}

/// Byte offset of `kf_path` inside FreeBSD's `struct kinfo_file`
/// (`sys/user.h`): `kf_structsize..kf_flags` (5 × `int`) + pad + `kf_offset`
/// (`i64`) + the 304-byte union + `kf_status`/pad/spare (8) +
/// `kf_cap_rights` (`cap_rights_t`, 2 × `u64`) + `_kf_cap_spare` (`u64`).
/// Identical on every FreeBSD architecture (all fields are fixed-width);
/// asserted against libc's layout under `cfg(target_os = "freebsd")` below.
#[cfg(any(test, target_os = "freebsd"))]
const KF_PATH_OFFSET: usize = 5 * 4 + 4 + 8 + 304 + 8 + 16 + 8;

/// Extract the cwd from the bytes `sysctl(KERN_PROC_CWD)` filled in: a
/// single `kinfo_file` whose `kf_structsize` (first `int`, native endian)
/// bounds the record and whose `kf_path` is a NUL-terminated string.
/// `None` for a short/empty reply or an empty path.
#[cfg(any(test, target_os = "freebsd"))]
fn cwd_from_kinfo(buf: &[u8]) -> Option<PathBuf> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let size = i32::from_ne_bytes(buf.get(..4)?.try_into().ok()?);
    let size = usize::try_from(size).ok()?;
    if size <= KF_PATH_OFFSET || size > buf.len() {
        return None;
    }
    let path = &buf[KF_PATH_OFFSET..size];
    let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
    (end > 0).then(|| PathBuf::from(OsStr::from_bytes(&path[..end])))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    use std::io;
    use std::path::PathBuf;

    pub(super) fn process_cwd(pid: u32) -> io::Result<PathBuf> {
        std::fs::read_link(format!("/proc/{pid}/cwd"))
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::{OsStr, c_char, c_int};
    use std::io;
    use std::mem::MaybeUninit;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    pub(super) fn process_cwd(pid: u32) -> io::Result<PathBuf> {
        let pid = c_int::try_from(pid)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pid out of range"))?;
        let mut info = MaybeUninit::<libc::proc_vnodepathinfo>::zeroed();
        let size = c_int::try_from(size_of::<libc::proc_vnodepathinfo>())
            .map_err(|_| io::Error::other("proc_vnodepathinfo too large"))?;
        // SAFETY: `info` is a writable buffer of exactly `size` bytes, which
        // is what `PROC_PIDVNODEPATHINFO` fills; the call writes nothing else.
        let written = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDVNODEPATHINFO,
                0,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        if written <= 0 {
            return Err(io::Error::last_os_error());
        }
        if written < size {
            return Err(io::Error::other(
                "proc_pidinfo returned a short vnodepathinfo",
            ));
        }
        // SAFETY: the kernel filled the whole struct (checked above) and it
        // started zeroed, so every byte is initialised plain-old-data.
        let info = unsafe { info.assume_init() };

        // `vip_path` is a NUL-terminated `char[MAXPATHLEN]`; the libc crate
        // models it as nested arrays, so view it through its address.
        let path = &info.pvi_cdir.vip_path;
        let len = size_of_val(path);
        let ptr = std::ptr::from_ref(path).cast::<c_char>().cast::<u8>();
        // SAFETY: `ptr` points at `len` initialised bytes inside `info`,
        // which outlives the slice.
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(len);
        if end == 0 {
            return Err(io::Error::other("proc_pidinfo returned an empty cwd"));
        }
        Ok(PathBuf::from(OsStr::from_bytes(&bytes[..end])))
    }
}

#[cfg(target_os = "freebsd")]
mod imp {
    use std::ffi::{c_int, c_void};
    use std::io;
    use std::mem::offset_of;
    use std::path::PathBuf;

    const _: () = assert!(
        offset_of!(libc::kinfo_file, kf_path) == super::KF_PATH_OFFSET,
        "kinfo_file layout differs from KF_PATH_OFFSET"
    );

    pub(super) fn process_cwd(pid: u32) -> io::Result<PathBuf> {
        let pid = c_int::try_from(pid)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pid out of range"))?;
        let mib: [c_int; 4] = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_CWD, pid];
        // The reply is exactly one `kinfo_file`; it is a plain-old-data
        // struct, so a zeroed byte buffer of its size is a valid target.
        let mut buf = vec![0u8; size_of::<libc::kinfo_file>()];
        let mut len = buf.len();
        // SAFETY: `mib` is a valid array of 4 ints, `buf` is a
        // writable buffer of `len` bytes and `len` is a valid in/out pointer;
        // no new value is passed (null/0).
        let rc = unsafe {
            libc::sysctl(
                mib.as_ptr(),
                4,
                buf.as_mut_ptr().cast::<c_void>(),
                &raw mut len,
                std::ptr::null(),
                0,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        buf.truncate(len);
        super::cwd_from_kinfo(&buf)
            .ok_or_else(|| io::Error::other("kern.proc.cwd returned no usable path"))
    }
}

/// OpenBSD: `sysctl([CTL_KERN, KERN_PROC_CWD, pid])` fills a NUL-terminated
/// path (sysctl(2)). Compiled only on OpenBSD; statically inspected, not run.
#[cfg(target_os = "openbsd")]
mod imp {
    use std::ffi::{OsStr, c_int, c_void};
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    pub(super) fn process_cwd(pid: u32) -> io::Result<PathBuf> {
        let pid = c_int::try_from(pid)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pid out of range"))?;
        let mib: [c_int; 3] = [libc::CTL_KERN, libc::KERN_PROC_CWD, pid];
        let mut buf = vec![0u8; libc::PATH_MAX as usize];
        let mut len = buf.len();
        // SAFETY: `mib` is a valid array of 3 ints, `buf` is a writable
        // buffer of `len` bytes and `len` is a valid in/out pointer; no new
        // value is passed (null/0).
        let rc = unsafe {
            libc::sysctl(
                mib.as_ptr(),
                3,
                buf.as_mut_ptr().cast::<c_void>(),
                &raw mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        buf.truncate(len);
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        if end == 0 {
            return Err(io::Error::other("kern.proc_cwd returned an empty path"));
        }
        Ok(PathBuf::from(OsStr::from_bytes(&buf[..end])))
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd"
)))]
mod imp {
    use std::io;
    use std::path::PathBuf;

    pub(super) fn process_cwd(_pid: u32) -> io::Result<PathBuf> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cwd probe is not supported on this platform",
        ))
    }
}

fn to_pid(pid: u32) -> io::Result<Pid> {
    i32::try_from(pid)
        .ok()
        .and_then(Pid::from_raw)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid pid"))
}

/// `kill(pid, signal)` with the portable signal mapped to the platform number.
pub fn kill(pid: u32, signal: mysh_proto::session::Signal) -> io::Result<()> {
    use mysh_proto::session::Signal as S;
    use rustix::process::Signal;

    let sig = match signal {
        S::Int => Signal::INT,
        S::Term => Signal::TERM,
        S::Hup => Signal::HUP,
        S::Kill => Signal::KILL,
        S::Quit => Signal::QUIT,
        S::Usr1 => Signal::USR1,
        S::Usr2 => Signal::USR2,
        S::Winch => Signal::WINCH,
    };
    rustix::process::kill_process(to_pid(pid)?, sig)?;
    Ok(())
}

/// Map a reaped child's status onto the wire type.
pub fn exit_status(status: std::process::ExitStatus) -> mysh_proto::session::ExitStatus {
    use mysh_proto::session::ExitStatus;
    use std::os::unix::process::ExitStatusExt;

    if let Some(signal) = status.signal() {
        return ExitStatus::Signal {
            signal,
            core_dumped: status.core_dumped(),
        };
    }
    // `code()` is `None` only for stopped/continued statuses, which `wait`
    // never yields; fall back to the raw wait status rather than invent one.
    ExitStatus::Code(status.code().unwrap_or_else(|| status.into_raw()))
}

/// Non-empty environment value, if set.
fn env_nonempty(key: &str) -> Option<OsString> {
    std::env::var_os(key).filter(|v| !v.is_empty())
}

/// Fields of the calling user's passwd entry we care about. Android is
/// deliberately left out: bionic returns synthetic entries.
#[derive(Debug, Default)]
struct Passwd {
    name: Option<String>,
    dir: Option<PathBuf>,
    shell: Option<PathBuf>,
}

#[cfg(not(target_os = "android"))]
fn passwd() -> Passwd {
    use std::ffi::{CStr, OsStr, c_char};
    use std::mem::MaybeUninit;
    use std::os::unix::ffi::OsStrExt;
    use std::ptr;

    /// Owned copy of a C string field, `None` for null or empty.
    ///
    /// # Safety
    /// `p` must be null or point at a NUL-terminated string.
    unsafe fn field(p: *const c_char) -> Option<Vec<u8>> {
        if p.is_null() {
            return None;
        }
        // SAFETY: non-null and NUL-terminated by the caller's contract.
        let bytes = unsafe { CStr::from_ptr(p) }.to_bytes();
        (!bytes.is_empty()).then(|| bytes.to_vec())
    }

    const MAX_BUF: usize = 1 << 20;
    let uid = rustix::process::getuid().as_raw();
    let mut buf: Vec<c_char> = vec![0; 1024];
    loop {
        let mut pwd = MaybeUninit::<libc::passwd>::zeroed();
        let mut result: *mut libc::passwd = ptr::null_mut();
        // SAFETY: `pwd` is a valid out-pointer, `buf` is a writable buffer of
        // `buf.len()` bytes that outlives every pointer stored into `pwd`,
        // and `result` is a valid out-pointer. The reentrant variant touches
        // no global state.
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                pwd.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                &raw mut result,
            )
        };
        if rc == libc::ERANGE {
            if buf.len() >= MAX_BUF {
                return Passwd::default();
            }
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || result.is_null() {
            return Passwd::default();
        }
        // SAFETY: rc == 0 with a non-null `result` means `getpwuid_r`
        // initialised `pwd`; its string fields point into `buf`, which is
        // still alive while we copy them out.
        let pwd = unsafe { pwd.assume_init() };
        // SAFETY: the fields are null or NUL-terminated strings inside `buf`.
        let (name, dir, shell) =
            unsafe { (field(pwd.pw_name), field(pwd.pw_dir), field(pwd.pw_shell)) };
        return Passwd {
            name: name.and_then(|b| String::from_utf8(b).ok()),
            dir: dir.map(|b| PathBuf::from(OsStr::from_bytes(&b))),
            shell: shell.map(|b| PathBuf::from(OsStr::from_bytes(&b))),
        };
    }
}

#[cfg(target_os = "android")]
fn passwd() -> Passwd {
    Passwd::default()
}

/// Shell to spawn for `Shell` sessions: `override_path` → `$SHELL` → passwd
/// (not on Android) → `/bin/sh` (`/system/bin/sh` on Android).
pub fn login_shell(override_path: Option<&Path>) -> PathBuf {
    if let Some(path) = override_path {
        return path.to_path_buf();
    }
    if let Some(shell) = env_nonempty("SHELL") {
        return PathBuf::from(shell);
    }
    if let Some(shell) = passwd().shell {
        return shell;
    }
    PathBuf::from(if cfg!(target_os = "android") {
        "/system/bin/sh"
    } else {
        "/bin/sh"
    })
}

/// `$HOME` → passwd (not on Android) → `/data/local/tmp` on Android → `/`.
pub fn home_dir() -> PathBuf {
    if let Some(home) = env_nonempty("HOME") {
        return PathBuf::from(home);
    }
    if let Some(dir) = passwd().dir {
        return dir;
    }
    if cfg!(target_os = "android") && Path::new("/data/local/tmp").is_dir() {
        return PathBuf::from("/data/local/tmp");
    }
    PathBuf::from("/")
}

/// `$USER` → `$LOGNAME` → passwd (not on Android) → `"user"`.
pub fn user_name() -> String {
    if let Some(name) = env_nonempty("USER").or_else(|| env_nonempty("LOGNAME")) {
        return name.to_string_lossy().into_owned();
    }
    passwd().name.unwrap_or_else(|| "user".to_owned())
}

/// `PATH` for session children when the server has none of its own.
pub fn default_path() -> &'static str {
    if cfg!(target_os = "android") {
        "/system/bin:/system/xbin"
    } else if cfg!(target_os = "freebsd") {
        // Ports live under `/usr/local`; sbin dirs are included because BSD
        // base tools (`ifconfig`, `sysctl`) live there and are not root-only.
        "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"
    } else if cfg!(target_os = "netbsd") {
        // pkgsrc lives under `/usr/pkg`.
        "/usr/pkg/bin:/usr/local/bin:/usr/bin:/bin:/usr/pkg/sbin:/usr/sbin:/sbin"
    } else if cfg!(target_os = "openbsd") {
        // Packages live under `/usr/local`, X under `/usr/X11R6`; same
        // sbin reasoning as FreeBSD.
        "/usr/local/bin:/usr/bin:/bin:/usr/X11R6/bin:/usr/local/sbin:/usr/sbin:/sbin"
    } else {
        "/usr/local/bin:/usr/bin:/bin"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cwd_of_self_matches_current_dir() {
        let probed = process_cwd(std::process::id()).expect("process_cwd");
        let expected = std::env::current_dir().expect("current_dir");
        assert_eq!(
            probed.canonicalize().expect("canonicalize probed"),
            expected.canonicalize().expect("canonicalize expected")
        );
    }

    #[test]
    fn cwd_of_bogus_pid_errors() {
        assert!(process_cwd(u32::MAX).is_err());
    }

    /// Build a synthetic `kinfo_file` reply: `kf_structsize` then the path
    /// at `KF_PATH_OFFSET`, padded to `total` bytes.
    fn kinfo(structsize: i32, path: &[u8], total: usize) -> Vec<u8> {
        let mut buf = vec![0u8; total];
        buf[..4].copy_from_slice(&structsize.to_ne_bytes());
        buf[KF_PATH_OFFSET..KF_PATH_OFFSET + path.len()].copy_from_slice(path);
        buf
    }

    #[test]
    fn kinfo_path_is_extracted_up_to_nul() {
        let total = KF_PATH_OFFSET + 1024;
        let size = i32::try_from(total).expect("fits");
        let buf = kinfo(size, b"/usr/home/me\0junk", total);
        assert_eq!(cwd_from_kinfo(&buf), Some(PathBuf::from("/usr/home/me")));
        // Unterminated path runs to `kf_structsize`.
        let short = kinfo(
            i32::try_from(KF_PATH_OFFSET + 2).expect("fits"),
            b"/x",
            total,
        );
        assert_eq!(cwd_from_kinfo(&short), Some(PathBuf::from("/x")));
    }

    #[test]
    fn kinfo_rejects_short_empty_or_oversized_replies() {
        let total = KF_PATH_OFFSET + 64;
        let size = i32::try_from(total).expect("fits");
        assert_eq!(cwd_from_kinfo(&[]), None);
        assert_eq!(cwd_from_kinfo(&[1, 0]), None);
        assert_eq!(cwd_from_kinfo(&kinfo(size, b"", total)), None);
        assert_eq!(
            cwd_from_kinfo(&kinfo(
                i32::try_from(KF_PATH_OFFSET).expect("fits"),
                b"/",
                total
            )),
            None
        );
        assert_eq!(cwd_from_kinfo(&kinfo(size + 1, b"/", total)), None);
        assert_eq!(cwd_from_kinfo(&kinfo(-1, b"/", total)), None);
    }

    #[test]
    fn login_shell_exists() {
        let shell = login_shell(None);
        assert!(shell.is_absolute(), "{shell:?}");
        assert!(shell.exists(), "{shell:?} does not exist");
        assert_eq!(
            login_shell(Some(Path::new("/opt/zsh"))),
            PathBuf::from("/opt/zsh")
        );
    }

    #[test]
    fn home_and_user_are_non_empty() {
        assert!(home_dir().is_absolute());
        assert_ne!(user_name(), "");
        assert_ne!(default_path(), "");
    }

    #[test]
    fn exit_status_maps_code_and_signal() {
        use mysh_proto::session::ExitStatus;
        use std::os::unix::process::ExitStatusExt;

        let code = std::process::ExitStatus::from_raw(7 << 8);
        assert_eq!(exit_status(code), ExitStatus::Code(7));
        let sig = std::process::ExitStatus::from_raw(15);
        assert_eq!(
            exit_status(sig),
            ExitStatus::Signal {
                signal: 15,
                core_dumped: false
            }
        );
    }

    #[test]
    fn kill_rejects_pid_zero_and_unknown_pid() {
        use mysh_proto::session::Signal;
        assert!(kill(0, Signal::Term).is_err());
        // Out of `pid_t` range: rejected before any syscall.
        assert!(kill(u32::MAX, Signal::Winch).is_err());
    }
}
