package amace.ghidra;

import amace.core.Abi;
import amace.core.Candidate;
import amace.core.FlowKind;
import amace.core.Semantics;
import amace.core.Site;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.UnknownContextException;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Exhaustive, non-mutating x86 decoder. Every initialized byte in the requested
 * start set is tried, including bytes occupied by existing code or data.
 */
public final class SupersetDecoder {
    public record Result(NavigableMap<Site, Candidate> candidates, long attempted,
            Map<String, Long> failures, long unsupportedSemantics) {
        public Result {
            candidates = Collections.unmodifiableNavigableMap(new TreeMap<>(candidates));
            failures = Collections.unmodifiableMap(new LinkedHashMap<>(failures));
        }
    }

    public Result decode(Program program, AddressSetView scope, Abi abi, TaskMonitor monitor)
            throws CancelledException {
        Objects.requireNonNull(program); Objects.requireNonNull(scope);
        Objects.requireNonNull(abi); Objects.requireNonNull(monitor);
        int bits = program.getLanguage().getLanguageDescription().getSize();
        if (!program.getLanguage().getProcessor().toString().equalsIgnoreCase("x86")
                || (bits != 32 && bits != 64) || bits != abi.bits()) {
            throw new IllegalArgumentException("AMACE requires a matching x86 32/64-bit language and ABI");
        }
        AddressSetView initialized = program.getMemory().getAllInitializedAddressSet();
        AddressSet starts = new AddressSet(scope).intersect(initialized);
        monitor.initialize(starts.getNumAddresses());
        monitor.setMessage("AMACE: exhaustive instruction decoding");
        PseudoDisassembler disassembler = new PseudoDisassembler(program);
        PcodeLifter lifter = new PcodeLifter(program, abi);
        NavigableMap<Site, Candidate> candidates = new TreeMap<>();
        Map<String, Long> failures = new LinkedHashMap<>();
        long attempted = 0, unsupported = 0;
        for (Address start : starts.getAddresses(true)) {
            monitor.checkCancelled();
            attempted++;
            if ((attempted & 1023) == 0) monitor.setProgress(attempted);
            requireFixedMode(program, start, abi);
            try {
                // This overload creates a new processor context at EVERY offset.
                PseudoInstruction instruction = disassembler.disassemble(start);
                if (instruction == null) {
                    count(failures, "invalid_opcode");
                    continue;
                }
                int length = instruction.getLength();
                if (length < 1 || length > 15) {
                    count(failures, "invalid_length");
                    continue;
                }
                Address end = start.addNoWrap(length - 1);
                if (!initialized.contains(start, end)) {
                    count(failures, "insufficient_bytes");
                    continue;
                }
                // PseudoCodeUnit may zero-fill bytes unavailable to its buffer.
                // Independently read the exact initialized span from Memory.
                byte[] bytes = new byte[length];
                if (program.getMemory().getBytes(start, bytes) != length) {
                    count(failures, "insufficient_bytes");
                    continue;
                }
                if (!Arrays.equals(bytes, instruction.getBytes())) {
                    count(failures, "bytes_changed_during_decode");
                    continue;
                }
                var semantics = lifter.lift(instruction);
                if (!semantics.supported()) unsupported++;
                var targets = new ArrayList<Site>();
                for (Address target : instruction.getFlows()) targets.add(site(target));
                FlowKind kind = flow(instruction);
                if (kind == FlowKind.INDIRECT_CALL) {
                    for (Site imported : importedTargets(program, semantics, abi)) {
                        if (!targets.contains(imported)) targets.add(imported);
                    }
                }
                Address fallthrough = instruction.getFallThrough();
                var operands = new ArrayList<String>();
                for (int i = 0; i < instruction.getNumOperands(); i++) {
                    operands.add(instruction.getDefaultOperandRepresentation(i));
                }
                Candidate candidate = new Candidate(site(start), bytes,
                    instruction.getMnemonicString(), String.join(", ", operands),
                    kind, targets,
                    fallthrough == null ? null : site(fallthrough), semantics);
                candidates.put(candidate.site(), candidate);
            }
            catch (InsufficientBytesException e) { count(failures, "insufficient_bytes"); }
            catch (UnknownInstructionException e) { count(failures, "invalid_opcode"); }
            catch (UnknownContextException e) { count(failures, "unknown_context"); }
            catch (MemoryAccessException e) { count(failures, "unreadable_bytes"); }
            catch (AddressOverflowException e) { count(failures, "insufficient_bytes"); }
        }
        monitor.setProgress(attempted);
        return new Result(candidates, attempted, failures, unsupported);
    }

    private static void count(Map<String, Long> counts, String reason) {
        counts.merge(reason, 1L, Long::sum);
    }

    static void requireFixedMode(Program program, Address address, Abi abi) {
        requireContext(program, address, "addrsize", abi.bits() == 64 ? 2 : 1, true);
        requireContext(program, address, "opsize", 1, true);
        requireContext(program, address, "longMode", abi.bits() == 64 ? 1 : 0, abi.bits() == 64);
    }

    /**
     * Resolve only loader-designated import slots. Ordinary constant memory
     * operands never become known call targets merely because they look like
     * pointers. This reads loader metadata, not mutable pointer contents.
     */
    private static java.util.Set<Site> importedTargets(Program program, Semantics semantics, Abi abi) {
        if (!semantics.supported() || semantics.indirectTarget() == null) return java.util.Set.of();
        Map<String, Long> constants = new HashMap<>();
        Map<String, Address> loadedSlots = new HashMap<>();
        for (Semantics.Op op : semantics.operations()) {
            if (op.output() == null) continue;
            String key = op.output().key();
            Long constant = fold(op, constants);
            Address slot = null;
            if (op.opcode().equals("LOAD") && op.inputs().size() >= 2
                    && op.output().size() == abi.wordSize()) {
                Long spaceId = constant(op.inputs().get(0), constants);
                Long offset = constant(op.inputs().get(1), constants);
                if (spaceId != null && offset != null) {
                    AddressSpace space = program.getAddressFactory().getAddressSpace(spaceId.intValue());
                    if (space != null && space.isMemorySpace()) {
                        try { slot = space.getAddress(offset); }
                        catch (RuntimeException ignored) { /* Not a representable import slot. */ }
                    }
                }
            }
            else if (op.opcode().equals("COPY") && op.inputs().size() == 1
                    && op.output().size() == abi.wordSize() && op.inputs().get(0).size() == abi.wordSize()) {
                slot = loadedSlots.get(op.inputs().get(0).key());
            }
            if (constant == null) constants.remove(key); else constants.put(key, constant);
            if (slot == null) loadedSlots.remove(key); else loadedSlots.put(key, slot);
        }
        Address slot = loadedSlots.get(semantics.indirectTarget().key());
        if (slot == null) return java.util.Set.of();
        var result = new LinkedHashSet<Site>();
        boolean imported = false;
        for (var symbol : program.getSymbolTable().getSymbols(slot)) {
            if (symbol.getSource() == SourceType.IMPORTED && symbol.getName().startsWith("__imp_")) {
                imported = true;
            }
        }
        for (var reference : program.getReferenceManager().getReferencesFrom(slot)) {
            if (reference.getSource() == SourceType.IMPORTED && reference.isExternalReference()) {
                imported = true;
                result.add(site(reference.getToAddress()));
            }
        }
        if (imported) result.add(site(slot));
        return result;
    }

    private static Long fold(Semantics.Op op, Map<String, Long> constants) {
        if (op.inputs().isEmpty()) return null;
        Long a = constant(op.inputs().get(0), constants);
        if (a == null) return null;
        Long b = op.inputs().size() < 2 ? null : constant(op.inputs().get(1), constants);
        Long value = switch (op.opcode()) {
            case "COPY", "INT_ZEXT" -> a;
            case "INT_ADD" -> b == null ? null : a + b;
            case "INT_SUB" -> b == null ? null : a - b;
            case "INT_AND" -> b == null ? null : a & b;
            case "INT_OR" -> b == null ? null : a | b;
            case "INT_XOR" -> b == null ? null : a ^ b;
            default -> null;
        };
        return value == null ? null : truncate(value, op.output().size());
    }

    private static Long constant(Semantics.Value value, Map<String, Long> constants) {
        if (value.kind() == Semantics.Kind.CONSTANT) return truncate(value.constant(), value.size());
        return constants.get(value.key());
    }

    private static long truncate(long value, int size) {
        return size >= 8 ? value : value & ((1L << (size * 8)) - 1);
    }

    private static void requireContext(Program program, Address address, String name,
            int expected, boolean required) {
        Register register = program.getLanguage().getRegister(name);
        if (register == null && !required) return;
        var value = register == null ? null
            : program.getProgramContext().getValue(register, address, false);
        if (value == null || !value.equals(java.math.BigInteger.valueOf(expected))) {
            throw new IllegalArgumentException("AMACE requires a fixed x86 default context; incompatible "
                + name + " at " + address + " (expected " + expected + ")");
        }
    }

    private static FlowKind flow(PseudoInstruction instruction) {
        FlowType flow = instruction.getFlowType();
        if (flow.isCall()) return flow.isComputed() ? FlowKind.INDIRECT_CALL : FlowKind.CALL;
        if (flow.isJump()) {
            if (flow.isComputed()) return FlowKind.INDIRECT_JUMP;
            return flow.isConditional() ? FlowKind.CONDITIONAL_JUMP : FlowKind.JUMP;
        }
        if (flow.isTerminal()) {
            for (PcodeOp op : instruction.getPcode()) {
                if (op.getOpcode() == PcodeOp.RETURN) return FlowKind.RETURN;
            }
            return FlowKind.HALT;
        }
        return FlowKind.NORMAL;
    }

    public static Site site(Address address) {
        return new Site(address.getAddressSpace().getName(), address.getOffset());
    }

    public static Address address(Program program, Site site) {
        AddressSpace space = program.getAddressFactory().getAddressSpace(site.space());
        if (space == null) throw new IllegalArgumentException("Unknown address space: " + site.space());
        return space.getAddress(site.offset());
    }
}
