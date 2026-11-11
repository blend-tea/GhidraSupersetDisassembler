// Exercises the packaged extension against actual Ghidra memory and Listing APIs.
// @category AMACE.Tests

import amace.core.*;
import amace.ghidra.*;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public class AmaceIntegrationTest extends GhidraScript {
    private void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private Set<Address> instructionStarts() {
        Set<Address> result = new TreeSet<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext()) result.add(it.next().getAddress());
        return result;
    }

    private Map<Address, AddressSet> functionBodies() {
        Map<Address, AddressSet> result = new TreeMap<>();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            result.put(f.getEntryPoint(), new AddressSet(f.getBody()));
        }
        return result;
    }

    private Set<Address> addresses(Address base, int... offsets) {
        Set<Address> result = new TreeSet<>();
        for (int offset : offsets) result.add(base.add(offset));
        return result;
    }

    @Override
    protected void run() throws Exception {
        // GhidraScript starts a transaction before run(). Close that empty
        // wrapper so each service invocation owns its atomic transaction.
        // Ghidra transactions are nested entries, not independent savepoints.
        end(true);
        String[] args = getScriptArgs();
        require(args.length == 3 || args.length == 4, "Arguments: ABI entry format [success-file]");
        Abi abi = Abi.valueOf(args[0]);
        Address base = toAddr(args[1]);
        boolean raw = args[2].equals("raw");
        require(base != null && currentProgram.getMemory().contains(base), "Fixture entry was not loaded");
        require(currentProgram.getDefaultPointerSize() * 8 == abi.bits(), "Wrong imported instruction mode");
        if (abi.bits() == 64 && !args[2].equals("elf")) {
            require(Long.compareUnsigned(base.getOffset(), 0xffffffffL) > 0, "High-address fixture lost its base");
        }

        AmaceAnalysisService service = new AmaceAnalysisService();
        AddressSet scope = new AddressSet(base, base.add(25));
        AnalysisOptions options = raw
                ? new AnalysisOptions(abi, Set.of(SupersetDecoder.site(base)), true)
                : AnalysisOptions.defaults();
        if (!raw) {
            require(AmaceAnalysisService.detectAbi(currentProgram) == abi, "ELF/PE ABI detection differs");
            require(AmaceAnalysisService.defaultScope(currentProgram).contains(base, base.add(24)),
                    "Default scope omitted executable fixture bytes");
        }
        Set<Address> originalInstructions = instructionStarts();
        Map<Address, AddressSet> originalFunctions = functionBodies();
        require(originalInstructions.isEmpty(), "Run this fixture with -noanalysis");
        if (raw) {
            boolean rejected = false;
            try { service.run(currentProgram, scope, AnalysisOptions.defaults(), monitor); }
            catch (AnalysisException expected) { rejected = true; }
            require(rejected, "Raw input accepted an unspecified ABI/entry");
        }
        boolean nestedRejected = false;
        int callerTransaction = currentProgram.startTransaction("Fixture caller-owned transaction");
        try {
            try { service.run(currentProgram, scope, options, monitor); }
            catch (AnalysisException expected) { nestedRejected = true; }
        } finally {
            currentProgram.endTransaction(callerTransaction, true);
        }
        require(nestedRejected, "Applying inside an unrelated caller transaction was accepted");
        require(instructionStarts().equals(originalInstructions) && functionBodies().equals(originalFunctions),
                "Rejected nested application changed the Program");

        // Cancel after the first instruction is inserted, not merely before the
        // run. A correctly nested transaction must undo that partial write.
        TaskMonitor cancelling = new TaskMonitorAdapter(true) {
            @Override public void checkCancelled() throws CancelledException {
                super.checkCancelled();
                if (!instructionStarts().equals(originalInstructions)) {
                    cancel();
                    throw new CancelledException();
                }
            }
        };
        boolean cancelled = false;
        try {
            service.run(currentProgram, scope, options, cancelling);
        } catch (CancelledException expected) {
            cancelled = true;
        }
        require(cancelled, "Cancellation was not observed during application");
        require(instructionStarts().equals(originalInstructions), "Cancelled application left instructions behind");
        require(functionBodies().equals(originalFunctions), "Cancelled application left function changes behind");

        // A read-only report must retain all valid overlapping interpretations.
        AnalysisReport preview = service.run(currentProgram, scope,
                new AnalysisOptions(abi, options.trustedEntries(), false), monitor);
        require(instructionStarts().equals(originalInstructions), "Preview changed Listing");
        require(functionBodies().equals(originalFunctions), "Preview changed functions");
        require(preview.attempted() == 26, "Decoder did not visit every byte offset");
        if (abi.bits() == 64) {
            Candidate interior = preview.candidates().get(SupersetDecoder.site(base.add(2)));
            require(interior != null, "Overlapping interior instruction disappeared from superset");
            require(interior.length() == 2, "Interior instruction decoded in wrong mode");
        }
        SupersetDecoder.Result singleStart = new SupersetDecoder().decode(currentProgram,
                new AddressSet(base.add(1)), abi, monitor);
        require(singleStart.attempted() == 1 && singleStart.candidates().get(SupersetDecoder.site(base.add(1))) != null,
                "Selection boundary prevented decoding a complete mapped instruction");
        if (raw) {
            require(!preview.candidates().containsKey(SupersetDecoder.site(base.add(25))),
                    "Decoder fabricated bytes for incomplete final opcode");
        }

        AnalysisReport report = service.run(currentProgram, scope, options, monitor);
        AutoAnalysisManager.getAnalysisManager(currentProgram).waitForAnalysis(null, monitor);
        AmaceEngine.Facts entryFacts = report.analysis().facts().get(SupersetDecoder.site(base));
        AmaceEngine.Facts calleeFacts = report.analysis().facts().get(SupersetDecoder.site(base.add(20)));
        require(entryFacts != null && entryFacts.stackCompatible(), "Balanced entry frame failed stack analysis");
        require(calleeFacts != null && calleeFacts.stackCompatible() && calleeFacts.registersCompatible(),
                "Actual PUSH/POP P-code failed stack/register-preservation analysis");
        require(report.analysis().noReturnCalls().isEmpty(), "Ordinary returning call was marked non-returning");
        Set<Address> expectedStarts = abi.bits() == 64
                ? addresses(base, 0, 1, 4, 9, 11, 12, 20, 21, 23, 24)
                : addresses(base, 0, 1, 3, 8, 10, 11, 20, 21, 23, 24);
        require(instructionStarts().equals(expectedStarts),
                "Listing starts differ: expected " + expectedStarts + ", got " + instructionStarts() +
                "; decisions " + report.selection().decisions());
        Set<Address> selectedStarts = new TreeSet<>();
        for (Site site : report.selection().accepted()) selectedStarts.add(SupersetDecoder.address(currentProgram, site));
        require(selectedStarts.equals(expectedStarts), "Listing is not the exact accepted candidate set");
        Function entry = currentProgram.getFunctionManager().getFunctionAt(base);
        Function callee = currentProgram.getFunctionManager().getFunctionAt(base.add(20));
        require(entry != null && callee != null, "Expected entry and direct callee functions");
        require(entry.getBody().equals(new AddressSet(base, base.add(abi.bits() == 64 ? 12 : 11))),
                "Entry body includes padding/callee or omits its return: " + entry.getBody());
        require(callee.getBody().equals(new AddressSet(base.add(20), base.add(24))), "Callee body differs");

        Map<Address, AddressSet> appliedFunctions = functionBodies();
        require(currentProgram.canUndo(), "AMACE application has no Undo transaction");
        currentProgram.undo();
        require(instructionStarts().equals(originalInstructions) && functionBodies().equals(originalFunctions),
                "One Undo did not revert the whole AMACE application");
        require(currentProgram.canRedo(), "AMACE Undo has no Redo transaction");
        currentProgram.redo();
        require(instructionStarts().equals(expectedStarts) && functionBodies().equals(appliedFunctions),
                "One Redo did not restore the whole AMACE application");
        entry = currentProgram.getFunctionManager().getFunctionAt(base);

        int metadataTx = currentProgram.startTransaction("Fixture user metadata");
        try {
            entry.setName("fixture_user_entry", SourceType.USER_DEFINED);
            entry.setComment("Preserve this user comment across AMACE runs.");
        } finally {
            currentProgram.endTransaction(metadataTx, true);
        }

        Map<Address, AddressSet> expectedFunctions = functionBodies();
        require(expectedFunctions.size() == 2, "Unjustified extra function entries: " + expectedFunctions);
        AnalysisReport repeated = service.run(currentProgram, scope, options, monitor);
        require(repeated.createdInstructions() == 0 && repeated.createdFunctions() == 0,
                "Repeated run should be idempotent");
        require(instructionStarts().equals(expectedStarts) && functionBodies().equals(expectedFunctions),
                "Repeated run changed the projection");
        require(currentProgram.getFunctionManager().getFunctionAt(base).getName().equals("fixture_user_entry"),
                "Repeated run replaced a user-defined function name");
        require(currentProgram.getFunctionManager().getFunctionAt(base).getComment().contains("Preserve this"),
                "Repeated run replaced a user comment");

        // A user-defined data item in the middle of the previous instruction
        // must remain data. SourceType on functions cannot justify clearing it.
        int movLength = abi.bits() == 64 ? 3 : 2;
        int tx = currentProgram.startTransaction("Fixture conflict");
        try {
            Listing listing = currentProgram.getListing();
            listing.clearCodeUnits(base.add(1), base.add(movLength), false);
            listing.createData(base.add(1), new ArrayDataType(ByteDataType.dataType, movLength, 1));
        } finally {
            currentProgram.endTransaction(tx, true);
        }
        AnalysisReport conflict = service.run(currentProgram, scope, options, monitor);
        require(currentProgram.getListing().getDefinedDataAt(base.add(1)) != null, "Defined data was overwritten");
        require(currentProgram.getListing().getInstructionAt(base.add(1)) == null, "Conflict was silently disassembled");
        require(!conflict.conflicts().isEmpty() || conflict.selection().decisions().values().stream().anyMatch(d -> !d.accepted()),
                "Conflict has no reported reason");

        // Real SLEIGH P-code must preserve the distinction between writing AL
        // and defining the whole AX/EAX/RAX pointer register. Decode both tiny
        // functions in a separate block, without invoking a native backend.
        Address partial = base.add(0x20000), full = partial.add(0x20);
        byte[] partialCode = abi.bits() == 64
                ? new byte[]{(byte)0xb0, 1, 0x48, (byte)0x8b, 0, (byte)0xc3}
                : new byte[]{(byte)0xb0, 1, (byte)0x8b, 0, (byte)0xc3};
        byte[] fullCode = abi.bits() == 64
                ? new byte[]{(byte)0xb8, 1, 0, 0, 0, 0x48, (byte)0x8b, 0, (byte)0xc3}
                : new byte[]{(byte)0xb8, 1, 0, 0, 0, (byte)0x8b, 0, (byte)0xc3};
        int microTx = currentProgram.startTransaction("Fixture P-code examples");
        try {
            currentProgram.getMemory().createInitializedBlock("partial_register", partial,
                    new ByteArrayInputStream(partialCode), partialCode.length, monitor, false);
            currentProgram.getMemory().createInitializedBlock("full_register", full,
                    new ByteArrayInputStream(fullCode), fullCode.length, monitor, false);
        } finally {
            currentProgram.endTransaction(microTx, true);
        }
        AddressSet microScope = new AddressSet(partial, partial.add(partialCode.length - 1));
        microScope.add(full, full.add(fullCode.length - 1));
        SupersetDecoder.Result micro = new SupersetDecoder().decode(currentProgram, microScope, abi, monitor);
        AmaceEngine.Analysis microAnalysis = new AmaceEngine().analyze(micro.candidates().values(), abi,
                Set.of(), Set.of(), () -> {});
        String pointerRegister = abi.bits() == 64 ? "rax" : "eax";
        require(microAnalysis.facts().get(SupersetDecoder.site(partial)).requiredRegisters().contains(pointerRegister),
                "Partial AL write incorrectly defined the whole pointer register");
        require(!microAnalysis.facts().get(SupersetDecoder.site(full)).requiredRegisters().contains(pointerRegister),
                "Full EAX write did not define/zero-extend the pointer register");
        println("AMACE_INTEGRATION_PASS " + currentProgram.getName() + " " + report.summary());
        if (args.length == 4) Files.writeString(Path.of(args[3]), "PASS\n" + report.summary() + "\n");
    }
}
