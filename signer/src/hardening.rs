//! Process-level security hardening (std-only).
//!
//! - Memory locking (`mlock` / `munlock`) to prevent swapping key material.
//! - Core-dump and ptrace disabling.
//! - Signal-based cleanup hooks for zeroizing cached keys on termination.

#[cfg(feature = "std")]
use std::sync::{Mutex, OnceLock};

#[cfg(feature = "std")]
type CleanupHooks = Mutex<Vec<Box<dyn Fn() + Send>>>;

#[cfg(feature = "std")]
static CLEANUP_HOOKS: OnceLock<CleanupHooks> = OnceLock::new();

#[cfg(feature = "std")]
fn hooks() -> &'static Mutex<Vec<Box<dyn Fn() + Send>>> {
    CLEANUP_HOOKS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Register a cleanup function to run on termination signals.
#[cfg(feature = "std")]
pub fn register_cleanup(f: impl Fn() + Send + 'static) {
    hooks().lock().expect("lock poisoned").push(Box::new(f));
}

#[cfg(feature = "std")]
fn run_cleanup_hooks() {
    if let Some(hooks) = CLEANUP_HOOKS.get() {
        if let Ok(hooks) = hooks.lock() {
            for hook in hooks.iter() {
                hook();
            }
        }
    }
}

/// Install signal handlers for graceful cleanup on SIGTERM/SIGINT/etc.
///
/// Spawns a background thread. Subsequent calls are no-ops.
#[cfg(all(feature = "std", unix))]
pub fn install_signal_handlers() {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
    use signal_hook::iterator::Signals;
    use std::sync::atomic::{AtomicBool, Ordering};

    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }

    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        run_cleanup_hooks();
        default_hook(info);
    }));

    let mut signals = Signals::new([SIGTERM, SIGINT, SIGHUP, SIGQUIT])
        .expect("failed to register signal handlers");

    std::thread::Builder::new()
        .name("signer-signal-handler".into())
        .spawn(move || {
            if let Some(sig) = signals.forever().next() {
                eprintln!("signer: signal {sig}, zeroizing key material");
                run_cleanup_hooks();
                std::process::exit(128 + sig);
            }
        })
        .expect("failed to spawn signal handler thread");
}

/// No-op on non-Unix or without `std`.
#[cfg(not(all(feature = "std", unix)))]
pub fn install_signal_handlers() {}

/// Report of which hardening measures succeeded.
#[derive(Debug)]
pub struct HardeningReport {
    /// Whether core dumps were disabled.
    pub core_dumps_disabled: bool,
    /// Whether ptrace attachment was disabled.
    pub ptrace_disabled: bool,
}

/// Apply all available process hardening measures.
#[cfg(all(feature = "std", unix))]
pub fn harden_process() -> HardeningReport {
    let core_dumps_disabled = disable_core_dumps();
    let ptrace_disabled = disable_ptrace();
    HardeningReport {
        core_dumps_disabled,
        ptrace_disabled,
    }
}

/// No-op on non-Unix or without `std`.
#[cfg(not(all(feature = "std", unix)))]
pub fn harden_process() -> HardeningReport {
    HardeningReport {
        core_dumps_disabled: false,
        ptrace_disabled: false,
    }
}

#[cfg(all(feature = "std", target_os = "linux"))]
fn disable_core_dumps() -> bool {
    #[allow(unsafe_code)]
    unsafe {
        let prctl_ok = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0;
        let rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        let rlimit_ok = libc::setrlimit(libc::RLIMIT_CORE, &rlim) == 0;
        prctl_ok && rlimit_ok
    }
}

#[cfg(all(feature = "std", target_os = "macos"))]
fn disable_core_dumps() -> bool {
    #[allow(unsafe_code)]
    unsafe {
        let rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &rlim) == 0
    }
}

#[cfg(all(feature = "std", unix, not(target_os = "linux"), not(target_os = "macos")))]
fn disable_core_dumps() -> bool {
    #[allow(unsafe_code)]
    unsafe {
        let rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &rlim) == 0
    }
}

#[cfg(all(feature = "std", target_os = "linux"))]
fn disable_ptrace() -> bool {
    true // PR_SET_DUMPABLE=0 already prevents ptrace
}

#[cfg(all(feature = "std", target_os = "macos"))]
fn disable_ptrace() -> bool {
    #[cfg(not(debug_assertions))]
    {
        const PT_DENY_ATTACH: libc::c_int = 31;
        #[allow(unsafe_code)]
        unsafe {
            libc::ptrace(PT_DENY_ATTACH, 0, core::ptr::null_mut(), 0) == 0
        }
    }
    #[cfg(debug_assertions)]
    true
}

#[cfg(all(feature = "std", unix, not(target_os = "linux"), not(target_os = "macos")))]
fn disable_ptrace() -> bool {
    false
}

/// Lock a memory region to prevent swapping.
#[cfg(all(feature = "std", unix))]
pub fn mlock_slice(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    #[allow(unsafe_code)]
    let ret = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
    ret == 0
}

/// No-op on non-Unix.
#[cfg(not(all(feature = "std", unix)))]
pub fn mlock_slice(_ptr: *const u8, _len: usize) -> bool {
    false
}

/// Unlock a previously mlocked memory region.
#[cfg(all(feature = "std", unix))]
pub fn munlock_slice(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    #[allow(unsafe_code)]
    unsafe {
        libc::munlock(ptr as *const libc::c_void, len);
    }
}

/// No-op on non-Unix.
#[cfg(not(all(feature = "std", unix)))]
pub fn munlock_slice(_ptr: *const u8, _len: usize) {}
