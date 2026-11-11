package amace.ghidra;

import amace.core.*;
import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.SystemUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

/** Shared GUI/headless pipeline. No ordinary recursive disassembler is used. */
public final class AmaceAnalysisService {
    private static final Set<String> NORETURN_NAMES = Set.of("exit", "_exit", "_Exit", "abort",
        "quick_exit", "__assert_fail", "__stack_chk_fail", "__fortify_fail", "__cxa_throw",
        "__cxa_rethrow", "std::terminate", "terminate", "ExitProcess", "ExitThread",
        "RaiseFailFastException", "RtlExitUserProcess", "RtlExitUserThread");

    public AnalysisReport run(Program program, AddressSetView scope, AnalysisOptions options,
            TaskMonitor monitor) throws CancelledException, AnalysisException {
        Objects.requireNonNull(program); Objects.requireNonNull(options); Objects.requireNonNull(monitor);
        if (program.isClosed()) throw new AnalysisException("Program is closed");
        int bits = program.getLanguage().getLanguageDescription().getSize();
        if (!program.getLanguage().getProcessor().toString().equalsIgnoreCase("x86")
                || (bits != 32 && bits != 64)) {
            throw new AnalysisException("Only x86 32-bit and 64-bit languages are supported");
        }
        Abi abi = options.abi() == null ? detectAbi(program) : options.abi();
        if (abi.bits() != bits) throw new AnalysisException("ABI bitness does not match the imported language");
        if (isRaw(program) && (options.abi() == null || options.trustedEntries().isEmpty() || scope == null)) {
            throw new AnalysisException("Raw Binary requires an explicit ABI, analysis range and entry address");
        }
        AddressSet capturedScope = new AddressSet(scope == null ? defaultScope(program) : scope)
            .intersect(program.getMemory().getAllInitializedAddressSet());
        if (capturedScope.isEmpty()) throw new AnalysisException("Analysis scope has no initialized memory");
        for (Site entry : options.trustedEntries()) {
            if (!capturedScope.contains(SupersetDecoder.address(program, entry))) {
                throw new AnalysisException("Entry is outside the analysis range: " + entry);
            }
        }
        AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
        if (SystemUtilities.isInHeadlessMode()) {
            requireIndependentTransaction(program, options);
            // In headless mode waitForAnalysis directly runs the queue and saves
            // task times in OptionsDB; unlike the GUI it does not wrap a worker.
            int drainTx = program.startTransaction("Finish pending analysis before AMACE");
            boolean drained = false;
            try {
                manager.waitForAnalysis(null, monitor);
                monitor.checkCancelled();
                drained = true;
            }
            finally { program.endTransaction(drainTx, drained); }
        }
        else manager.waitForAnalysis(null, monitor);
        monitor.checkCancelled();
        requireIndependentTransaction(program, options);
        AtomicReference<AnalysisReport> result = new AtomicReference<>();
        try {
            boolean success = manager.scheduleWorker(new AnalysisWorker() {
                @Override public String getWorkerName() { return "AMACE Superset Analysis"; }
                @Override public boolean analysisWorkerCallback(Program p, Object context, TaskMonitor m)
                        throws Exception {
                    result.set(analyzeAndApply(p, capturedScope, abi, options, m));
                    return true;
                }
            }, null, false, monitor);
            if (!success && result.get() == null) {
                monitor.checkCancelled();
                throw new AnalysisException("AMACE worker did not complete");
            }
        }
        catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof CancelledException c) throw c;
            if (cause instanceof CancelledRun c) throw c.cancelled;
            if (cause instanceof AnalysisException a) throw a;
            throw new AnalysisException("AMACE analysis failed: " + cause.getMessage(), cause);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AnalysisException("AMACE worker interrupted", e);
        }
        catch (CancelledException e) {
            // Cancellation after a successful atomic commit must still report that commit.
            if (result.get() == null) throw e;
        }
        if (result.get() == null) throw new AnalysisException("AMACE produced no report");
        return result.get();
    }

    private static void requireIndependentTransaction(Program program, AnalysisOptions options) throws AnalysisException {
        if (options.apply() && program.getCurrentTransactionInfo() != null) {
            throw new AnalysisException("Apply AMACE outside an existing Program transaction. "
                + "A GhidraScript must call end(true) before invoking this service so cancellation can roll back immediately.");
        }
    }

    private AnalysisReport analyzeAndApply(Program program, AddressSet scope, Abi abi,
            AnalysisOptions options, TaskMonitor monitor) throws Exception {
        try {
            var decoded = new SupersetDecoder().decode(program, scope, abi, monitor);
            var candidates = decoded.candidates();
            var roots = trustedRoots(program, scope);
            roots.addAll(options.trustedEntries());
            for (Site root : options.trustedEntries()) {
                if (!candidates.containsKey(root)) throw new AnalysisException("Entry does not decode: " + root);
            }
            var possible = possibleEntries(program, candidates, roots, abi, monitor);
            var knownNoReturn = knownNoReturnTargets(program, monitor);
            Runnable cancellation = () -> {
                try { monitor.checkCancelled(); }
                catch (CancelledException e) { throw new CancelledRun(e); }
            };
            monitor.setMessage("AMACE: backward semantic analyses");
            var analysis = new AmaceEngine().analyze(candidates.values(), abi, knownNoReturn,
                possible.possible(), possible.strong(), cancellation);
            var conflicts = new ArrayList<String>();
            var blocked = blockedCandidates(program, scope, candidates, analysis.noReturnCalls(), conflicts, monitor);
            monitor.setMessage("AMACE: conservative instruction selection");
            var selection = new CandidateSelector().select(candidates, roots, analysis.inferredEntries(),
                analysis.noReturnCalls(), blocked, cancellation);
            int instructions = 0, functions = 0;
            if (options.apply()) {
                // Re-decode before the first mutation; selected prototypes are not retained
                // for the whole superset. Current bytes and context must still match.
                var prototypes = new TreeMap<Site,PseudoInstruction>();
                var newlyCreated = new HashSet<Site>();
                PseudoDisassembler disassembler = new PseudoDisassembler(program);
                PcodeLifter validationLifter = new PcodeLifter(program, abi);
                for (Site site : selection.accepted()) {
                    monitor.checkCancelled();
                    Candidate candidate = candidates.get(site);
                    SupersetDecoder.requireFixedMode(program, SupersetDecoder.address(program, site), abi);
                    PseudoInstruction pseudo = disassembler.disassemble(SupersetDecoder.address(program, site));
                    if (pseudo == null || pseudo.getLength() != candidate.length()
                            || !Arrays.equals(pseudo.getBytes(), candidate.bytes())
                            || !pseudo.getMnemonicString().equals(candidate.mnemonic())
                            || !validationLifter.lift(pseudo).equals(candidate.semantics())) {
                        throw new AnalysisException("Bytes or processor context changed at " + site);
                    }
                    prototypes.put(site, pseudo);
                }
                int tx = program.startTransaction("Apply AMACE disassembly");
                boolean commit = false;
                try {
                    monitor.setMessage("AMACE: applying selected instructions");
                    Listing listing = program.getListing();
                    for (var entry : prototypes.entrySet()) {
                        monitor.checkCancelled();
                        Address address = SupersetDecoder.address(program, entry.getKey());
                        if (listing.getInstructionAt(address) != null) continue;
                        PseudoInstruction pseudo = entry.getValue();
                        listing.createInstruction(address, pseudo.getPrototype(), pseudo, pseudo, 0);
                        newlyCreated.add(entry.getKey());
                        instructions++;
                    }
                    monitor.checkCancelled();
                    functions = applyFunctions(program, candidates, selection, conflicts, monitor);
                    for (Site call : analysis.noReturnCalls()) {
                        monitor.checkCancelled();
                        if (!selection.accepted().contains(call) || !newlyCreated.contains(call)) continue;
                        Instruction instruction = listing.getInstructionAt(SupersetDecoder.address(program, call));
                        if (instruction != null && instruction.getFallThrough() != null) instruction.setFallThrough(null);
                    }
                    monitor.checkCancelled();
                    commit = true;
                }
                finally { program.endTransaction(tx, commit); }
            }
            return new AnalysisReport(candidates, analysis, selection, decoded.failures(), decoded.attempted(),
                instructions, functions, conflicts, options.apply(), program.getName());
        }
        catch (CancelledRun e) { throw e.cancelled; }
    }

    private static Set<Site> blockedCandidates(Program program, AddressSetView scope,
            Map<Site,Candidate> candidates, Set<Site> noReturnCalls, List<String> conflicts, TaskMonitor monitor) throws Exception {
        Set<Site> blocked = new TreeSet<>();
        Listing listing = program.getListing();
        for (Candidate candidate : candidates.values()) {
            monitor.checkCancelled();
            Address start = SupersetDecoder.address(program, candidate.site());
            Address end;
            try { end = start.addNoWrap(candidate.length() - 1); }
            catch (AddressOverflowException e) { blocked.add(candidate.site()); continue; }
            if (!scope.contains(start, end)) { blocked.add(candidate.site()); continue; }
            Instruction existing = listing.getInstructionAt(start);
            if (existing != null && existing.getLength() == candidate.length()
                    && Arrays.equals(existing.getBytes(), candidate.bytes())
                    && existing.getMnemonicString().equals(candidate.mnemonic())) {
                boolean expectedFallthrough = Objects.equals(existing.getFallThrough(),
                    candidate.fallthrough() == null ? null : SupersetDecoder.address(program, candidate.fallthrough()));
                boolean compatibleNoReturn = noReturnCalls.contains(candidate.site()) && existing.getFallThrough() == null;
                if (existing.getFlowOverride() == FlowOverride.NONE && (expectedFallthrough || compatibleNoReturn)) continue;
                blocked.add(candidate.site());
                conflicts.add(candidate.site() + ": existing flow override preserved");
                continue;
            }
            if (!listing.isUndefined(start, end)) {
                blocked.add(candidate.site());
                conflicts.add(candidate.site() + ": existing instruction or defined data preserved");
            }
        }
        return blocked;
    }

    private static int applyFunctions(Program program, Map<Site,Candidate> candidates,
            CandidateSelector.Selection selection, List<String> conflicts, TaskMonitor monitor) throws Exception {
        int created = 0;
        FunctionManager manager = program.getFunctionManager();
        for (var entry : selection.functionBodies().entrySet()) {
            monitor.checkCancelled();
            Address start = SupersetDecoder.address(program, entry.getKey());
            AddressSet body = new AddressSet();
            for (Site site : entry.getValue()) {
                Address address = SupersetDecoder.address(program, site);
                body.add(address, address.addNoWrap(candidates.get(site).length() - 1));
            }
            boolean overlap = false;
            var existingBodies = manager.getFunctionsOverlapping(body);
            while (existingBodies.hasNext()) {
                if (!existingBodies.next().getEntryPoint().equals(start)) { overlap = true; break; }
            }
            if (overlap) { conflicts.add(entry.getKey() + ": pre-existing function body preserved"); continue; }
            Function existing = manager.getFunctionAt(start);
            if (existing != null) {
                if (!existing.getBody().equals(body)) {
                    SourceType source = existing.getSymbol().getSource();
                    if (source != SourceType.USER_DEFINED && body.contains(existing.getBody())) existing.setBody(body);
                    else conflicts.add(entry.getKey() + ": existing function boundary preserved");
                }
                continue;
            }
            Symbol symbol = program.getSymbolTable().getPrimarySymbol(start);
            String name = symbol != null && !symbol.isDynamic() ? symbol.getName() : null;
            manager.createFunction(name, start, body, SourceType.ANALYSIS);
            created++;
        }
        return created;
    }

    private static Set<Site> trustedRoots(Program program, AddressSetView scope) {
        Set<Site> result = new TreeSet<>();
        var entries = program.getSymbolTable().getExternalEntryPointIterator();
        while (entries.hasNext()) {
            Address address = entries.next();
            MemoryBlock block = program.getMemory().getBlock(address);
            if (scope.contains(address) && block != null && (block.isExecute() || isRaw(program))) result.add(SupersetDecoder.site(address));
        }
        var functions = program.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            if (scope.contains(function.getEntryPoint())) result.add(SupersetDecoder.site(function.getEntryPoint()));
        }
        var symbols = program.getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (symbol.getSymbolType() == SymbolType.FUNCTION && scope.contains(symbol.getAddress())) result.add(SupersetDecoder.site(symbol.getAddress()));
        }
        return result;
    }

    /** DASSA-style structural candidates; not a claim to reproduce DASSA's orchestration. */
    private record EntryCandidates(Set<Site> possible, Set<Site> strong) {}

    private static EntryCandidates possibleEntries(Program program, Map<Site,Candidate> candidates,
            Set<Site> roots, Abi abi, TaskMonitor monitor) throws CancelledException {
        Set<Site> possible = new TreeSet<>(roots);
        Set<Site> strong = new TreeSet<>(roots);
        for (Candidate candidate : candidates.values()) {
            monitor.checkCancelled();
            if ((candidate.site().offset() & 15) == 0) possible.add(candidate.site());
            byte[] bytes = candidate.bytes();
            boolean framePush = bytes.length == 1 && (bytes[0] & 255) == 0x55;
            if (framePush) {
                possible.add(candidate.site());
                Candidate next = candidates.get(candidate.fallthrough());
                if (next != null && next.mnemonic().equalsIgnoreCase("MOV")) {
                    String operands = next.operands().replace(" ", "").toLowerCase(Locale.ROOT);
                    if (operands.equals(abi.framePointer() + "," + abi.stackPointer())) strong.add(candidate.site());
                }
            }
            if (candidate.flow() == FlowKind.CALL) {
                for (Site target : candidate.targets()) if (candidates.containsKey(target)) possible.add(target);
            }
            if ((candidate.flow() == FlowKind.CALL || candidate.flow() == FlowKind.INDIRECT_CALL)
                    && candidate.fallthrough() != null && candidates.containsKey(candidate.fallthrough())) {
                possible.add(candidate.fallthrough());
            }
        }
        // Code-address constants may be unaligned; inspect initialized data without
        // trusting any of these values as definite function entries.
        int width = abi.wordSize();
        byte[] pointer = new byte[width];
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (!block.isInitialized()) continue;
            long count = block.getSize() - width + 1;
            for (long offset = 0; offset < count; offset++) {
                if ((offset & 1023) == 0) monitor.checkCancelled();
                try {
                    if (program.getMemory().getBytes(block.getStart().add(offset), pointer) != width) continue;
                    long value = 0;
                    for (int i = width - 1; i >= 0; i--) value = (value << 8) | (pointer[i] & 255L);
                    Site target = new Site(program.getAddressFactory().getDefaultAddressSpace().getName(), value);
                    if (candidates.containsKey(target)) { possible.add(target); strong.add(target); }
                }
                catch (ghidra.program.model.mem.MemoryAccessException e) { break; }
            }
        }
        return new EntryCandidates(possible, strong);
    }

    private static Set<Site> knownNoReturnTargets(Program program, TaskMonitor monitor) throws CancelledException {
        Set<Site> result = new TreeSet<>();
        var symbols = program.getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext()) {
            monitor.checkCancelled();
            Symbol symbol = symbols.next();
            String name = symbol.getName();
            String undecorated = name.replaceFirst("^__imp_", "").replaceFirst("@\\d+$", "");
            if (NORETURN_NAMES.contains(name) || NORETURN_NAMES.contains(undecorated)
                    || NORETURN_NAMES.contains(undecorated.replaceFirst("^_", ""))) result.add(SupersetDecoder.site(symbol.getAddress()));
        }
        var functions = program.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            if (function.hasNoReturn()) result.add(SupersetDecoder.site(function.getEntryPoint()));
        }
        var externalReferences = program.getReferenceManager().getExternalReferences();
        while (externalReferences.hasNext()) {
            monitor.checkCancelled();
            var reference = externalReferences.next();
            if (reference.getSource() == SourceType.IMPORTED
                    && result.contains(SupersetDecoder.site(reference.getToAddress()))) {
                result.add(SupersetDecoder.site(reference.getFromAddress()));
            }
        }
        return result;
    }

    public static boolean isRaw(Program program) {
        String format = program.getExecutableFormat().toLowerCase(Locale.ROOT);
        return format.contains("raw") || format.contains("binaryloader");
    }

    public static Abi detectAbi(Program program) throws AnalysisException {
        String format = program.getExecutableFormat().toLowerCase(Locale.ROOT);
        if (isRaw(program)) throw new AnalysisException("Choose an explicit ABI for Raw Binary");
        boolean windows = format.contains("portable executable") || format.equals("pe");
        if (!windows && !format.contains("elf") && !format.contains("executable and linking")) {
            throw new AnalysisException("Supported input formats: ELF, PE and Raw Binary");
        }
        int bits = program.getLanguage().getLanguageDescription().getSize();
        return bits == 64 ? (windows ? Abi.WINDOWS_X64 : Abi.SYSV_X64)
                : (windows ? Abi.WINDOWS_X86 : Abi.SYSV_X86);
    }

    public static AddressSet defaultScope(Program program) {
        AddressSet result = new AddressSet();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (block.isInitialized() && (block.isExecute() || isRaw(program))) result.add(block.getStart(), block.getEnd());
        }
        return result;
    }

    private static final class CancelledRun extends RuntimeException {
        final CancelledException cancelled;
        CancelledRun(CancelledException cancelled) { super(cancelled); this.cancelled = cancelled; }
    }
}
