package amace.ghidra;

import amace.core.Abi;
import amace.core.Semantics;
import amace.core.Semantics.Kind;
import amace.core.Semantics.Op;
import amace.core.Semantics.Value;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Converts raw SLEIGH P-code into the dependency-free AMACE micro-CFG. */
public final class PcodeLifter {
    private static final Set<Integer> UNSUPPORTED = Set.of(
        PcodeOp.CALLOTHER, PcodeOp.CPOOLREF, PcodeOp.NEW, PcodeOp.SEGMENTOP,
        PcodeOp.MULTIEQUAL, PcodeOp.INDIRECT);
    private final Program program;
    private final Abi abi;

    public PcodeLifter(Program program, Abi abi) { this.program = program; this.abi = abi; }

    public Semantics lift(Instruction instruction) {
        PcodeOp[] raw;
        try { raw = instruction.getPcode(); }
        catch (RuntimeException e) { return Semantics.unknown(); }
        if (raw == null) return Semantics.unknown();
        // Treat the machine call as one ABI operation. Its SLEIGH return-address
        // push/store must not become a permanent caller stack adjustment.
        for (int i = 0; i < raw.length; i++) {
            PcodeOp op = raw[i];
            if (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) {
                if (!instruction.getMnemonicString().equalsIgnoreCase("CALL")) {
                    return Semantics.unknown();
                }
                if (op.getOpcode() == PcodeOp.CALL) {
                    return new Semantics(List.of(), true, null, callAdjustment(instruction));
                }
                try {
                    boolean[] needed = targetSlice(raw, i, op.getInput(0));
                    List<Op> setup = new ArrayList<>();
                    boolean supported = true;
                    for (int j = 0; j < i; j++) {
                        if (!needed[j]) continue;
                        if (isLocalBranch(raw[j], instruction) || isTransfer(raw[j])) {
                            supported = false;
                            setup.add(new Op("UNKNOWN", null, List.of()));
                            continue;
                        }
                        Op lifted = operation(raw[j], -1);
                        supported &= !lifted.opcode().equals("UNKNOWN");
                        setup.add(lifted);
                    }
                    return new Semantics(setup, supported, value(op.getInput(0)),
                        callAdjustment(instruction));
                }
                catch (RuntimeException e) { return Semantics.unknown(); }
            }
            if (op.getOpcode() == PcodeOp.RETURN) {
                // The analysis starts at the return boundary, before the hardware
                // return pop. The callee's RET n cleanup is a caller-side fact.
                return instruction.getMnemonicString().equalsIgnoreCase("RET")
                    ? Semantics.identity() : Semantics.unknown();
            }
        }
        List<Op> result = new ArrayList<>();
        Value indirectTarget = null;
        int[] indices = new int[raw.length + 1];
        int next = 0;
        for (int i = 0; i < raw.length; i++) {
            indices[i] = next;
            if (!isTransfer(raw[i]) || isLocalBranch(raw[i], instruction)) next++;
        }
        indices[raw.length] = next;
        boolean supported = true;
        try {
            for (int i = 0; i < raw.length; i++) {
                PcodeOp op = raw[i];
                if (op.getOpcode() == PcodeOp.BRANCHIND) {
                    indirectTarget = value(op.getInput(0));
                }
                if (isTransfer(op) && !isLocalBranch(op, instruction)) continue;
                int branch = -1;
                if (isLocalBranch(op, instruction)) {
                    long target = op.getInput(0).isConstant() ? (long) i + signed(op.getInput(0))
                        : op.getInput(0).getAddress().equals(instruction.getMinAddress()) ? 0 : raw.length;
                    if (target < 0 || target > raw.length) {
                        result.add(new Op("UNKNOWN", null, List.of()));
                        supported = false;
                        continue;
                    }
                    branch = indices[(int) target];
                }
                Op lifted = operation(op, branch);
                supported &= !lifted.opcode().equals("UNKNOWN");
                result.add(lifted);
            }
        }
        catch (RuntimeException e) { return Semantics.unknown(); }
        return new Semantics(result, supported, indirectTarget, 0L);
    }

    private Long callAdjustment(Instruction instruction) {
        if (abi.bits() == 64) return 0L;
        for (var target : instruction.getFlows()) {
            Function function = program.getFunctionManager().getFunctionAt(target);
            if (function != null && function.isStackPurgeSizeValid()) {
                int purge = function.getStackPurgeSize();
                if (purge != Function.UNKNOWN_STACK_DEPTH_CHANGE
                        && purge != Function.INVALID_STACK_DEPTH_CHANGE) return (long) purge;
            }
            if (function != null && "__cdecl".equals(function.getCallingConventionName())) return 0L;
        }
        // An ELF System V i386 call uses caller cleanup. Win32 may use RET n;
        // unknown cleanup there must not silently be assumed to be zero.
        return abi == Abi.SYSV_X86 ? 0L : null;
    }

    private Op operation(PcodeOp op, int branch) {
        List<Value> inputs = new ArrayList<>();
        for (Varnode input : op.getInputs()) inputs.add(value(input));
        Value output = op.getOutput() == null ? null : value(op.getOutput());
        String opcode = UNSUPPORTED.contains(op.getOpcode()) ? "UNKNOWN" : op.getMnemonic();
        // Win64 preserves the low 128 bits of XMM6-15; wider lanes need
        // separate summaries, so do not claim full AVX register preservation.
        if (hasWideVector(output) || inputs.stream().anyMatch(PcodeLifter::hasWideVector)) {
            return new Op("UNKNOWN", output, inputs, branch);
        }
        // SLEIGH folds absolute memory operands into address-space varnodes.
        // Make ordinary MOV/indirect-target loads and stores explicit for the
        // abstract memory rules and import-slot provenance.
        if (op.getOpcode() == PcodeOp.COPY && inputs.size() == 1) {
            if (inputs.get(0).kind() == Kind.MEMORY
                    && output != null && output.kind() != Kind.MEMORY) {
                Value memory = inputs.get(0);
                return new Op("LOAD", output, memoryAddress(memory), branch);
            }
            if (output != null && output.kind() == Kind.MEMORY
                    && inputs.get(0).kind() != Kind.MEMORY) {
                var store = new ArrayList<>(memoryAddress(output));
                store.add(inputs.get(0));
                return new Op("STORE", null, store, branch);
            }
        }
        List<Value> dataInputs = branch >= 0 && isTransfer(op) ? inputs.subList(1, inputs.size()) : inputs;
        if ((output != null && output.kind() == Kind.MEMORY)
                || dataInputs.stream().anyMatch(input -> input.kind() == Kind.MEMORY)) {
            opcode = "UNKNOWN";
        }
        return new Op(opcode, output, inputs, branch);
    }

    private List<Value> memoryAddress(Value memory) {
        var space = program.getAddressFactory().getAddressSpace(memory.name());
        if (space == null || !space.isMemorySpace()) throw new IllegalArgumentException("unknown memory space");
        return List.of(Value.constant(space.getSpaceID(), 8),
            Value.constant(memory.constant(), abi.wordSize()));
    }

    private static boolean hasWideVector(Value value) {
        return value != null && value.kind() == Kind.REGISTER
            && value.name().startsWith("xmm") && value.size() > 16;
    }

    private Value value(Varnode node) {
        int size = node.getSize();
        if (size < 1) throw new IllegalArgumentException("zero-width P-code varnode");
        if (node.isConstant()) return Value.constant(node.getOffset(), size);
        if (node.isUnique()) return Value.temporary(node.getOffset(), size);
        if (node.isRegister()) {
            Register register = program.getLanguage().getRegister(node.getAddress(), size);
            if (register == null) throw new IllegalArgumentException("unknown register storage");
            Register base = register.getBaseRegister();
            String name = base.getName().toLowerCase(Locale.ROOT);
            int baseSize = base.getMinimumByteSize();
            int offset = (int) (node.getOffset() - base.getAddress().getOffset());
            if (abi.bits() == 32 && baseSize == 8) {
                String truncated = switch (name) {
                    case "rax" -> "eax"; case "rbx" -> "ebx";
                    case "rcx" -> "ecx"; case "rdx" -> "edx";
                    case "rsi" -> "esi"; case "rdi" -> "edi";
                    case "rsp" -> "esp"; case "rbp" -> "ebp";
                    case "rip" -> "eip"; default -> name;
                };
                if (!truncated.equals(name)) { name = truncated; baseSize = 4; }
            }
            if (name.matches("[xyz]mm[0-9]+")) {
                name = "xmm" + name.substring(3);
                baseSize = Math.max(16, offset + size);
            }
            return new Value(Kind.REGISTER, name, offset, size,
                Math.max(baseSize, offset + size), 0);
        }
        return new Value(Kind.MEMORY, node.getAddress().getAddressSpace().getName(),
            0, size, size, node.getOffset());
    }

    private static boolean isTransfer(PcodeOp op) {
        return switch (op.getOpcode()) {
            case PcodeOp.BRANCH, PcodeOp.CBRANCH, PcodeOp.BRANCHIND,
                 PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.RETURN -> true;
            default -> false;
        };
    }

    private static boolean isLocalBranch(PcodeOp op, Instruction instruction) {
        if ((op.getOpcode() != PcodeOp.BRANCH && op.getOpcode() != PcodeOp.CBRANCH)
                || op.getNumInputs() == 0) return false;
        if (op.getInput(0).isConstant()) return true;
        var target = op.getInput(0).getAddress();
        var start = instruction.getMinAddress();
        // SLEIGH also uses real inst_start/inst_next addresses for local
        // constructs such as REP loops and CMOV's conditional assignment.
        return target.getAddressSpace().equals(start.getAddressSpace())
            && (target.equals(start) || target.getOffset() - start.getOffset() == instruction.getLength());
    }

    private static long signed(Varnode node) {
        int shift = 64 - Math.min(64, node.getSize() * 8);
        return (node.getOffset() << shift) >> shift;
    }

    /** Backward dependency slice of a CALLIND target, excluding the call push. */
    private static boolean[] targetSlice(PcodeOp[] ops, int call, Varnode target) {
        boolean[] result = new boolean[call];
        Set<String> needed = new HashSet<>();
        if (target.isUnique()) needed.add(key(target));
        for (int i = call - 1; i >= 0; i--) {
            PcodeOp op = ops[i];
            if (op.getOutput() == null || !needed.remove(key(op.getOutput()))) continue;
            result[i] = true;
            for (Varnode input : op.getInputs()) {
                if (input.isUnique()) needed.add(key(input));
            }
        }
        if (!needed.isEmpty()) throw new IllegalArgumentException("unresolved CALLIND temporary");
        return result;
    }

    private static String key(Varnode node) {
        return node.getAddress().getAddressSpace().getName() + ":" + node.getOffset()
            + ":" + node.getSize();
    }
}
