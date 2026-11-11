# Validation report

**English** | [日本語](VALIDATION_ja.md) | [README](../README.md)

Validated on 2026-11-11 using Ghidra 12.2 PUBLIC, Temurin Java 25.0.5, Gradle 9.1.0, and Linux x86-64.

## Build and core suites

`clean check buildExtension` passed. The framework-free golden suites are available through `coreTest` and the standard `test`/`check` tasks.

- AMACE engine: 45 checks, including paper Table 4 depth/maximum/count tuples, branch intersection, SP/BP preservation, dynamic stack allocation, partial registers, internal CFGs, unknown facts, non-return propagation, and a 20,000-node graph.
- Instruction selection: 41 checks, including iteration-order invariance, equal-priority overlap deferral, evidence tiers, reachability after conflicts, shared tails, and indirect transfers.
- Abstract domains: bounds, aggregation, saturating counts, overflow, and strict-majority regressions passed.
- All bundled Java GhidraScripts compiled against actual Ghidra 12.2 APIs.

## Packaged headless validation

`scripts/test-headless.sh` loads the extension ZIP as an isolated external module and creates temporary projects without changing an existing Ghidra installation or user settings.

| Input | 32-bit | 64-bit |
| --- | --- | --- |
| Raw Binary | Passed | Passed |
| ELF | Passed | Passed |
| PE | Passed | Passed |

Each fixture verified exhaustive candidate generation and overlaps, exact application of 10 known instruction starts and two functions, function bodies, returning calls, rollback during application, single-step Undo/Redo, repeat execution, user names/comments, and existing data. ELF/PE use loader roots and ABI detection; Raw uses explicit configuration.

The packaged `RunAmace.java` CLI was executed directly. Its JSONL schema version, 26 attempted offsets, full candidate set, overlapping interior instruction, and exact accepted set were checked.

All 84 real-SLEIGH assertions in `AmaceLifterTest.java` passed. These cover both CPU widths, high addresses, holes and uninitialized tails, CALL/RET and CALL-next, indirect transfers, aliases, CMOV/REP internal CFGs, loader IAT metadata, context rejection, and 128/256-bit vector handling.

## GUI validation

Under virtual X11, the real PluginTool and AmacePlugin were constructed and tested for Program activation, the Raw dialog, the eight-column asynchronous table, filtering, disposal, and consumer release.

`guiTest` also executed a 4,096-instruction analysis. Normal completion and cancellation each opened exactly one modal window, repeat execution was blocked, normal completion registered all 4,096 instructions, and cancellation left the Listing unchanged. The old implementation reproduced two competing modal windows; the fix removes the extension's outer TaskLauncher so AutoAnalysisManager owns the window.

Run `./gradlew guiTest` with an X11 `DISPLAY` to execute the GUI regression.

## Evaluation limits

These are functional and regression checks using small known byte sequences and paper examples. They are not a large-corpus accuracy/performance evaluation or evidence of output parity with the AMACE research backend. Unsupported P-code effects remain unknown.
