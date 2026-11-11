// Exercises the real Ghidra SLEIGH decoder and the AMACE micro-CFG adapter.
// @category AMACE.Tests
import amace.core.Abi;
import amace.core.Candidate;
import amace.core.Semantics;
import amace.ghidra.SupersetDecoder;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import java.math.BigInteger;
import java.util.HexFormat;

public class AmaceLifterTest extends GhidraScript {
    private int assertions;

    @Override protected void run() throws Exception {
        for (int bits : new int[] {32, 64}) {
            decoderBounds(bits);
            controlTransfers(bits);
            aliasesAndMicroBranches(bits);
            importedPointers(bits);
            contextMismatch(bits);
        }
        println("AMACE_LIFTER_TESTS_PASSED assertions=" + assertions);
        if (getScriptArgs().length > 0) {
            java.nio.file.Files.writeString(java.nio.file.Path.of(getScriptArgs()[0]),
                "PASS\n" + assertions + "\n");
        }
    }

    private void decoderBounds(int bits) throws Exception {
        long high = bits == 64 ? 0xffff800000001000L : 0xf0001000L;
        try (Fixture f = fixture(bits, high, "b801000000c3")) {
            var result = decode(f, new AddressSet(f.start));
            check(result.attempted() == 1, "exact set of instruction start addresses");
            Candidate mov = result.candidates().get(SupersetDecoder.site(f.start));
            check(mov != null && mov.length() == 5, "decode uses real bytes past selection end");
            check(mov.site().offset() == high, "unsigned high address remains exact");
            check(f.program.getListing().getNumInstructions() == 0, "decode does not define instructions");
        }
        try (Fixture f = fixture(bits, 0x1000, "b8")) {
            int tx = f.program.startTransaction("uninitialized tail");
            try {
                f.program.getMemory().createUninitializedBlock("tail", f.start.add(1), 8, false);
            }
            finally { f.program.endTransaction(tx, true); }
            var result = decode(f, new AddressSet(f.start));
            check(result.candidates().isEmpty(), "uninitialized tail is never zero-padded into a MOV");
            check(result.attempted() == 1 && !result.failures().isEmpty(), "truncated opcode failure recorded");
        }
        try (Fixture f = fixture(bits, 0x1000, "b8")) {
            int tx = f.program.startTransaction("memory hole");
            try {
                f.program.getMemory().createInitializedBlock("afterHole", f.start.add(5), 1,
                    (byte) 0xc3, TaskMonitor.DUMMY, false);
            }
            finally { f.program.endTransaction(tx, true); }
            var result = decode(f, new AddressSet(f.start, f.start.add(5)));
            check(result.attempted() == 2, "unmapped bytes do not become candidate starts");
            check(!result.candidates().containsKey(SupersetDecoder.site(f.start)), "decode never bridges a memory hole");
        }
    }

    private void controlTransfers(int bits) throws Exception {
        for (String bytes : new String[] {"ffe0", "ffd4", "ff1424", "e805000000", "c3", "cf"}) {
            try (Fixture f = fixture(bits, 0x1000, bytes)) {
                Candidate c = candidate(f);
                check(c != null, "control-transfer fixture decodes: " + bytes);
                if (bytes.equals("ffe0")) {
                    check(c.semantics().indirectTarget() != null, "indirect jump retains target-definedness");
                    check(c.semantics().indirectTarget().name().equals(bits == 64 ? "rax" : "eax"),
                        "indirect jump target canonical register");
                }
                else if (bytes.startsWith("ff")) {
                    check(c.semantics().indirectTarget() != null, "indirect call retains target");
                    check(c.semantics().operations().stream().noneMatch(op -> op.opcode().equals("STORE")),
                        "call return-address store is removed");
                    check(c.semantics().operations().stream().noneMatch(op -> op.output() != null
                        && op.output().kind() == Semantics.Kind.REGISTER
                        && op.output().name().equals(bits == 64 ? "rsp" : "esp")),
                        "call return-address SP decrement is removed");
                }
                else if (bytes.equals("e805000000") || bytes.equals("c3")) {
                    check(c.semantics().operations().isEmpty() && c.semantics().supported(),
                        "near CALL/RET become atomic ABI operations: " + bits + "/" + bytes + " " + c.semantics());
                }
                else check(!c.semantics().supported(), "IRET never supplies ordinary function-return evidence");
            }
        }
        try (Fixture f = fixture(bits, 0x1000, "e800000000")) {
            Candidate c = candidate(f);
            check(c.flow() != amace.core.FlowKind.CALL && c.flow() != amace.core.FlowKind.INDIRECT_CALL,
                "CALL-next get-PC idiom is a stack operation, not an ordinary returning call: " + c.flow());
            check(c.semantics().operations().stream().anyMatch(op -> op.opcode().equals("STORE")),
                "CALL-next retains the pushed PC value");
        }
        if (bits == 64) {
            try (Fixture f = fixture(bits, 0x1000, "0f05")) {
                Candidate c = candidate(f);
                check(c != null && !c.semantics().supported(), "unknown syscall USEROP retained as unknown candidate");
            }
        }
    }

    private void aliasesAndMicroBranches(int bits) throws Exception {
        String register = bits == 64 ? "rax" : "eax";
        try (Fixture f = fixture(bits, 0x1000, "b412")) {
            Candidate c = candidate(f);
            check(c.semantics().operations().stream().anyMatch(op -> op.output() != null
                && op.output().name().equals(register) && op.output().byteOffset() == 1
                && op.output().size() == 1 && !op.output().fullRegister()),
                "AH write remains a partial base-register definition");
        }
        try (Fixture f = fixture(bits, 0x1000, "89d8")) {
            Candidate c = candidate(f);
            if (bits == 64) {
                check(c.semantics().operations().stream().anyMatch(op -> op.opcode().equals("INT_ZEXT")
                    && op.output().name().equals("rax") && op.output().fullRegister()),
                    "EAX writes include the SLEIGH full-RAX zero extension");
            }
            else check(c.semantics().operations().stream().anyMatch(op -> op.output() != null
                && op.output().name().equals("eax") && op.output().fullRegister()),
                "32-bit language uses EAX as a full register");
        }
        try (Fixture f = fixture(bits, 0x1000, bits == 64 ? "480f44c3" : "0f44c3")) {
            Candidate c = candidate(f);
            check(c.semantics().supported(), "CMOV micro-CFG is supported");
            check(c.semantics().operations().stream().anyMatch(op -> op.opcode().equals("CBRANCH")
                && op.branchTarget() >= 0 && op.branchTarget() <= c.semantics().operations().size()),
                "local conditional branch has a remapped operation index: " + c.semantics());
        }
        try (Fixture f = fixture(bits, 0x1000, "f3a4")) {
            Candidate c = candidate(f);
            check(c.semantics().operations().stream().anyMatch(op -> op.branchTarget() >= 0),
                "REP instruction retains its local micro-loop");
        }
        try (Fixture f = fixture(bits, 0x1000, "660f6fc6")) {
            check(candidate(f).semantics().supported(), "128-bit XMM moves retain modeled register effects");
        }
        if (bits == 64) {
            try (Fixture f = fixture(bits, 0x1000, "c5fd6f3500000000")) {
                check(!candidate(f).semantics().supported(),
                    "wide AVX absolute-memory loads remain unknown, including direct-memory COPY form");
            }
        }
    }

    private void importedPointers(int bits) throws Exception {
        String bytes = bits == 64 ? "ff150a000000c3" : "ff1510100000c3";
        try (Fixture f = fixture(bits, 0x1000, bytes + "00".repeat(17))) {
            Address slot = f.start.add(0x10);
            Candidate ordinary = candidate(f);
            check(ordinary.targets().isEmpty(), "ordinary constant pointer is not a resolved import");
            int tx = f.program.startTransaction("user import-looking label");
            var label = f.program.getSymbolTable().createLabel(slot, "__imp_ExitProcess", SourceType.USER_DEFINED);
            f.program.endTransaction(tx, true);
            check(candidate(f).targets().isEmpty(), "user import-looking label does not establish loader provenance");
            tx = f.program.startTransaction("loader import label");
            label.delete();
            f.program.getSymbolTable().createLabel(slot, "__imp_ExitProcess", SourceType.IMPORTED);
            f.program.endTransaction(tx, true);
            Candidate imported = candidate(f);
            check(imported.targets().contains(SupersetDecoder.site(slot)), "loader IAT slot is recorded as known target: "
                + bits + " " + imported.semantics() + " " + imported.targets());
            check(imported.flow() == amace.core.FlowKind.INDIRECT_CALL,
                "IAT resolution does not turn an indirect call into a direct-call function root");
            tx = f.program.startTransaction("loader external reference without import label");
            for (var symbol : f.program.getSymbolTable().getSymbols(slot)) symbol.delete();
            var external = f.program.getReferenceManager().addExternalReference(slot,
                "KERNEL32.dll", "ExitProcess", null, SourceType.IMPORTED, 0, RefType.DATA);
            f.program.endTransaction(tx, true);
            Candidate unlabeled = candidate(f);
            check(unlabeled.targets().contains(SupersetDecoder.site(slot)),
                "loader external reference establishes IAT provenance without __imp label");
            check(unlabeled.targets().contains(SupersetDecoder.site(external.getToAddress())),
                "loader external target is retained alongside its IAT slot");
        }
    }

    private void contextMismatch(int bits) throws Exception {
        try (Fixture f = fixture(bits, 0x1000, "90c3")) {
            var register = f.program.getLanguage().getRegister(bits == 64 ? "longMode" : "opsize");
            int tx = f.program.startTransaction("incompatible fixed mode");
            f.program.getProgramContext().setValue(register, f.start, f.start.add(1), BigInteger.ZERO);
            f.program.endTransaction(tx, true);
            boolean rejected = false;
            try { candidate(f); }
            catch (IllegalArgumentException expected) { rejected = true; }
            check(rejected, "mixed or 16-bit input context rejected before mutation");
            check(f.program.getListing().getNumInstructions() == 0, "context rejection leaves Listing unchanged");
        }
    }

    private SupersetDecoder.Result decode(Fixture f, AddressSet range) throws Exception {
        return new SupersetDecoder().decode(f.program, range,
            f.bits == 64 ? Abi.SYSV_X64 : Abi.SYSV_X86, monitor);
    }

    private Candidate candidate(Fixture f) throws Exception {
        return decode(f, new AddressSet(f.start)).candidates().get(SupersetDecoder.site(f.start));
    }

    private Fixture fixture(int bits, long base, String hex) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID("x86:LE:" + bits + ":default"));
        ProgramDB program = new ProgramDB("lifter-fixture", language,
            language.getCompilerSpecByID(new CompilerSpecID("gcc")), this);
        Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(base);
        byte[] bytes = HexFormat.of().parseHex(hex);
        int tx = program.startTransaction("fixture memory");
        try {
            program.getMemory().createInitializedBlock("text", start, bytes.length,
                (byte) 0, TaskMonitor.DUMMY, false);
            program.getMemory().setBytes(start, bytes);
        }
        finally { program.endTransaction(tx, true); }
        return new Fixture(program, start, bits);
    }

    private final class Fixture implements AutoCloseable {
        final ProgramDB program; final Address start; final int bits;
        Fixture(ProgramDB program, Address start, int bits) { this.program = program; this.start = start; this.bits = bits; }
        @Override public void close() { program.release(AmaceLifterTest.this); }
    }

    private void check(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }
}
