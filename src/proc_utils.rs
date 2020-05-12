use libc::{self, rlimit64};
use nix::errno;
#[cfg(target_family = "unix")]
use nix::sys::mman::{mlockall, MlockAllFlags};

/**
 * Attempt to lock all memory to prevent the system from
 * writing it on swap in unfortunate circumstances.
 * Best effort: if we don't have permissions to do it, move on.
 */
pub fn attempt_to_lock_memory() {
    #[cfg(target_family = "unix")]
    let _ = mlockall(MlockAllFlags::all());
}

pub fn disable_core_dump() -> Result<(), nix::Error> {
    let rlim = rlimit64 {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let res = unsafe { libc::setrlimit64(libc::RLIMIT_CORE, &rlim as *const _) };
    errno::Errno::result(res).map(drop)
}
