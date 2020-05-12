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
