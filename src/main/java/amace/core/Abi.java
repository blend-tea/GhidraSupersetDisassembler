package amace.core;

import java.util.Set;

/** ABI boundary facts; register names are canonical SLEIGH base-register names, lower-case. */
public enum Abi {
    SYSV_X64(64, Set.of("rdi","rsi","rdx","rcx","r8","r9","rsp"), Set.of("rbx","rbp","r12","r13","r14","r15"), Set.of("rax","rdx","xmm0","xmm1")),
    WINDOWS_X64(64, Set.of("rcx","rdx","r8","r9","rsp"), Set.of("rbx","rbp","rdi","rsi","r12","r13","r14","r15","xmm6","xmm7","xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15"), Set.of("rax","xmm0")),
    SYSV_X86(32, Set.of("esp"), Set.of("ebx","ebp","esi","edi"), Set.of("eax","edx","st0")),
    WINDOWS_X86(32, Set.of("esp"), Set.of("ebx","ebp","esi","edi"), Set.of("eax","edx","st0"));
    private final int bits; private final Set<String> entryDefined, preserved, returns;
    Abi(int bits, Set<String> entryDefined, Set<String> preserved, Set<String> returns) {
        this.bits=bits; this.entryDefined=entryDefined; this.preserved=preserved; this.returns=returns;
    }
    public int bits() { return bits; }
    public int wordSize() { return bits / 8; }
    public String stackPointer() { return bits==64 ? "rsp" : "esp"; }
    public String framePointer() { return bits==64 ? "rbp" : "ebp"; }
    public Set<String> entryDefined() { return entryDefined; }
    public Set<String> preserved() { return preserved; }
    public Set<String> returns() { return returns; }
}
