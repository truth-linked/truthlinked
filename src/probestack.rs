#[no_mangle]
pub unsafe extern "C" fn __rust_probestack() {
    // Stack probing for macOS (x86_64)
    // Input: rax = number of bytes to allocate
    // Probes each 4KB page to ensure stack is committed
    core::arch::asm!(
        "2:",
        "sub rax, 4096",
        "test [rsp + rax], rax",
        "cmp rax, 4096",
        "ja 2b",
        "ret",
        options(noreturn)
    );
}
