# Usage guide

**English** | [日本語](usage_ja.md) | [README](../README.md)

## Input configuration

ELF and PE entry points come from loader metadata. The default ABI is System V for ELF and Windows for PE; bitness comes from the imported Language. Known per-function calling conventions inform effects such as stack cleanup. The default scope is initialized executable memory. Select a range in the Listing to restrict it.

Raw Binary has no reliable entry or ABI metadata, so its dialog requires:

| Field | Meaning |
| --- | --- |
| Entry address | The actual start address, within initialized memory in the analysis range |
| First / Last address | Inclusive analysis bounds |
| ABI | `SYSV_X86`, `SYSV_X64`, `WINDOWS_X86`, or `WINDOWS_X64`, matching the imported mode |

Use Ghidra's displayed address notation. The imported Language, bitness, and image base remain in effect.

## Candidate table

| Column | Meaning |
| --- | --- |
| Address / Bytes / Instruction | Decoded candidates, including overlapping starts not represented in the Listing |
| Pointer definedness | Register-definition requirements from backward analysis |
| Stack depth | Depth, maximum depth, and observation-count summaries |
| Callee-saved registers | Preservation and restoration facts for the ABI |
| Selection / Details | Acceptance or deferral reasons, unsupported effects, and uncertainty |

Filter by address, instruction, or reason; click column headers to sort. Double-click a row to navigate to its Program's Listing. Overlapping candidates cannot all be defined there, so navigation may land inside another accepted instruction.

The table is marked stale after Program changes and cleared when switching or closing Programs. Rerun analysis to refresh its facts.

## Applying results and existing Programs

AMACE is serialized with standard autoanalysis. Only its selected set is applied, and those changes do not trigger additional autoanalysis. Running standard Auto Analyze afterward can add or change results under Ghidra's own rules.

Ghidra's analysis manager owns the single modal progress/cancellation window. The extension does not launch a competing modal TaskLauncher, and repeat execution is disabled while a run is active.

Decoding does not modify the Program. Application uses one transaction and rolls back on failure or cancellation. GUI Undo/Redo can revert or restore the application. Conflicting existing instructions and defined data are preserved, with conflicts recorded in candidate decisions.

Entry and non-return evidence does not resolve every overlapping interpretation or shared function body. Instruction selection and function creation are separate: instructions can be retained while function creation is deferred because its body conflicts.

## Analysis boundaries

- Fixed 32-bit or 64-bit x86 mode is supported. This static analysis does not cover 16-bit mode, runtime mode changes, self-modifying code, or runtime-generated code.
- Missing or uninitialized bytes are not padded. A candidate may extend past the end of the selected start range into real mapped memory, but its entire instruction must be inside the application scope to be applied.
- Complete recovery of indirect targets or all functions is not guaranteed. External and unresolved transfers remain in the results.
- Unsupported P-code effects become unknown. Their decoded candidates remain available and are not analyzed as fake NOPs.
- AMACE backward analyses are distinct from the extension's Listing selection and function-body policy. Published paper metrics and output parity with the research C++ implementation are not claimed for this port.

## Headless arguments

`RunAmace.java` calls the same service as the GUI.

| Argument | Meaning |
| --- | --- |
| `--abi NAME` | Explicit ABI; required for Raw Binary |
| `--entry ADDRESS` | Additional trusted entry; required for Raw Binary |
| `--start ADDRESS --end ADDRESS` | Inclusive scope; required for Raw Binary |
| `--no-apply` | Decode, analyze, and select without applying |
| `--report PATH` | JSON Lines output: metadata, all candidates, and unresolved edges |

`-processor`, `-cspec`, `-loader`, and `-loader-baseAddr` are import options for `analyzeHeadless`, not script arguments. A Raw entry is an actual start within initialized memory loaded at the chosen image base and within the scope; it need not equal the image base.

## Java API

GUI and headless execution share this service:

```java
AnalysisReport report = new AmaceAnalysisService().run(
    program, scope, new AnalysisOptions(abi, trustedEntries, true), monitor);
```

Call with `apply=true` outside an existing Program transaction. The service manages serialization and application transactions. Invoke it on a background thread, not Swing's EDT.

GhidraScript starts an initial transaction. The bundled `RunAmace.java` closes it with `end(true)` before calling the service. Custom scripts must also allow the service to own application rollback rather than nesting it inside an unrelated transaction.

## Running validation

Configure Java 25 and Ghidra 12.2, then build and run the core golden/property suites:

```sh
./gradlew clean buildExtension coreTest
```

Test the packaged ZIP with:

```sh
scripts/test-headless.sh
```

Python 3 generates small known ELF, PE, and Raw fixtures in both CPU widths. The runner uses `analyzeHeadless -noanalysis` and an isolated external module in temporary projects, without installing into your normal Ghidra configuration.

Coverage includes exhaustive decoding, overlapping candidates, the exact accepted Listing set, function bodies, existing definitions, rollback, repeat execution, and Undo/Redo. Set `AMACE_KEEP_TEST_OUTPUT=1` to retain temporary output and logs.

The runner also checks the packaged production CLI/JSONL and real SLEIGH cases in `ghidra_scripts/AmaceLifterTest.java`: high addresses, range ends, memory holes, CALL/RET normalization, register aliases, P-code branches, unknown USEROPs, and calling conventions.

With an X11 `DISPLAY`, run `./gradlew guiTest` to check actual GUI execution, single-modal-window ownership, reentry protection, completion, and cancellation. See the [validation report](VALIDATION.md) for recorded results and evaluation limits.
