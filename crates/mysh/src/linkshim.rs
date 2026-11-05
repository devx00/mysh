//! Link-time shims for targets whose libc needs a nudge. They live in the
//! binary crate (not an rlib) so their object file is always on the link
//! line ahead of `libc.a`, which is what makes the override take effect
//! regardless of the linker's archive-resolution order.

/// musl resolves `clock_gettime` through the kernel's vDSO by calling this
/// internal function once (`src/internal/vdso.c`); a null return means "no
/// vDSO, use the system call". On 32-bit ARM some kernels — 4.1-era vendor
/// trees built in Thumb-2 — publish a vDSO whose function symbols lack the
/// Thumb bit, so the call enters Thumb code in ARM state and the process
/// dies inside the tokio runtime constructor, before `main` has printed
/// anything (the only symptom is a `SIGSEGV` at an address inside the vDSO
/// page, with `sp` thrown far away). Defining the symbol here keeps musl's
/// `vdso.o` out of the link: `clock_gettime` then always makes the system
/// call, a few microseconds that mysh never spends in a hot loop.
///
/// Only the 32-bit ARM musl builds carry this: aarch64 has no interworking
/// and no other target has shown the problem (docs/08-platform-matrix.md,
/// "Runtime notes").
#[cfg(all(target_os = "linux", target_env = "musl", target_arch = "arm"))]
#[allow(unsafe_code)]
// SAFETY: `no_mangle` only fixes the symbol name. The function is safe Rust
// with no preconditions and never reads its arguments; its one caller, musl's
// `cgt_init`, handles a null return as the documented "no vDSO" case.
#[unsafe(no_mangle)]
extern "C" fn __vdsosym(
    _version: *const core::ffi::c_char,
    _name: *const core::ffi::c_char,
) -> *mut core::ffi::c_void {
    core::ptr::null_mut()
}
