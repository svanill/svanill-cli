use libc::{self, rlimit64};
use nix::errno;
#[cfg(target_family = "unix")]
use nix::sys::mman::{mlockall, MlockAllFlags};

/**
 * Attempt to lock all memory to prevent the system from
 * writing it on swap in unfortunate circumstances.
 * Best effort: if we don't have permissions to do it, move on.
 */
pub fn attempt_to_lock_memory() -> bool {
    if cfg!(target_family = "unix") {
        mlockall(MlockAllFlags::all()).is_ok()
    } else {
        false
    }
}

pub fn disable_core_dump() -> Result<(), nix::Error> {
    let rlim = rlimit64 {
        rlim_cur: 0,
        rlim_max: 0,
    };

    let res = unsafe { libc::setrlimit64(libc::RLIMIT_CORE, &rlim as *const _) };
    errno::Errno::result(res).map(drop)?;

    // Set the state of the "dumpable" flag, which determines whether core dumps
    // are produced for the calling process upon delivery of a signal whose
    // default behavior is to produce a core dump.
    //
    // Processes that are not dumpable can not be attached
    // via `ptrace(2)` `PTRACE_ATTACH`; see `ptrace(2)` for further details.
    const SUID_DUMP_DISABLE: i32 = 0;
    let res = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, SUID_DUMP_DISABLE) };
    errno::Errno::result(res).map(drop)
}
