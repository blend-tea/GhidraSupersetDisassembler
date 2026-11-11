# GhidraSupersetDisassembler (GhidraAmace)

**English** | [日本語](README_ja.md)

A superset disassembly extension for Ghidra 12.2 and x86/x86-64. It decodes instructions at every byte offset, applies backward analyses based on AMACE using Java and P-code, preserves overlapping candidates, and automatically adds selected instructions and functions to the standard Listing.

This is an independent implementation based on [Superset Disassembly (Bauman et al., NDSS 2018)](https://personal.utdallas.edu/~hamlen/bauman18ndss.pdf) and [AMACE (Nguyen et al., PLDI 2026)](https://doi.org/10.1145/3808292). It brings the AMACE backward analyses featured by Google Research into Ghidra. Function-entry candidate generation and the final Listing selection policy are specific to this extension. This is not an official Google or Ghidra project.

## Requirements

- Ghidra **12.2**
- Java **25**; Gradle **9.1 or later** for building
- ELF, PE, or Raw Binary using a fixed **32-bit or 64-bit x86 mode**

Analysis runs inside Ghidra. The original AMACE backend, Python, Docker, and an external native analysis engine are not runtime dependencies.

## Installation and use

1. Download the extension ZIP from [GitHub Releases](https://github.com/blend-tea/GhidraSupersetDisassembler/releases). In the Ghidra Project window, open **File → Install Extensions**, add the ZIP, and restart Ghidra. For a local build, use the ZIP in `dist/`.
2. In CodeBrowser, enable `AmacePlugin` under **File → Configure → Configure All Plugins**.
3. Import a binary and **decline the standard Auto Analyze prompt**, then run **Tools → AMACE → Analyze and Apply**.
4. Inspect the **AMACE Superset Candidates** table. It supports sorting, text filtering, and double-click navigation to the Listing, with analysis facts and reasons for accepting or deferring each candidate.

ELF and PE default to initialized executable memory. Select a range in the Listing before running to restrict the scope. For Raw Binary, choose the correct Language, Compiler Spec, and base address during import, then supply an entry address, analysis range, and ABI in the extension's dialog.

## Build

```sh
export JAVA_HOME=/path/to/jdk-25
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.2_PUBLIC
./gradlew clean buildExtension coreTest
```

The extension ZIP is written to `dist/`. `coreTest` runs the semantic-analysis and instruction-selection regression suites without starting Ghidra.

## Headless use

The bundled script calls the same service as the GUI. Install the extension first and use `-noanalysis` to prevent standard autoanalysis from running before AMACE.

```sh
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" /path/to/projects AmaceDemo \
  -import /path/to/program.elf -noanalysis \
  -scriptPath /path/to/GhidraAmace/ghidra_scripts \
  -postScript RunAmace.java --report /path/to/report.jsonl
```

For Raw Binary, provide import options such as `-loader BinaryLoader -processor x86:LE:64:default -loader-baseAddr 100000`, and pass `--abi SYSV_X64 --entry 100000 --start 100000 --end 100fff` to the script. Addresses are hexadecimal and the range end is inclusive. `--no-apply` computes results without applying them to the Program. JSON Lines reports contain a metadata record followed by all candidates and unresolved edges.

## Interpreting results

- The superset retains every successfully decoded start offset in the selected instruction mode. The standard Listing receives a non-overlapping subset.
- Selection prioritizes trusted entries, direct callees reached from accepted code, and then AMACE-inferred entries. Equal-priority overlaps are deferred; shorter instructions or lower addresses do not break ties.
- Unresolved indirect transfers, unsupported P-code, and unrecognized stack effects remain unknown. Unknown facts alone do not establish a new function entry or a non-returning call.
- Existing conflicting instructions, defined data, function names, and signatures are preserved. The intended workflow is a freshly imported Program; destructive reconstruction of existing analysis is not provided.
- Listing selection is the extension's own integration policy. AMACE function-entry evidence is not proof that every selected instruction is correct.

See the [usage guide](docs/usage.md) for options, APIs, and limitations.

## Large binaries and memory use

Candidates, P-code, and analysis results for all offsets are kept in memory. Large inputs can exhaust the Java heap with `OutOfMemoryError: Java heap space`; this version has not been optimized for large-input memory use. Restrict the analysis range or set `GHIDRA_MAXMEM` according to available RAM and restart Ghidra. `GHIDRA_HEADLESS_MAXMEM` sets a headless-only limit. Increasing the heap does not guarantee that every input size will fit.

The [validation report](docs/VALIDATION.md) describes testing on small known byte sequences and its limits. Accuracy and performance figures from the research papers are not measurements of this implementation.

## References and attribution

- **AMACE**: Huan Nguyen, Soumyakant Priyadarshan, ChenCheng Jiang, R. Sekar. *Analyzing Bytes: Pre-Disassembly Static Binary Analysis*. Proceedings of the ACM on Programming Languages (PLDI), 2026. [DOI: 10.1145/3808292](https://doi.org/10.1145/3808292) / [Paper PDF](https://www.seclab.cs.sunysb.edu/seclab/pubs/amace.pdf) / [Google Research overview](https://research.google/pubs/analyzing-bytes-pre-disassembly-static-binary-analysis/) / [Authors' research implementation](https://github.com/nhuhuan/amace)
- **Superset Disassembly**: Erik Bauman, Zhiqiang Lin, Kevin W. Hamlen. *Superset Disassembly: Statically Rewriting x86 Binaries Without Heuristics*. NDSS, 2018. [Paper PDF](https://personal.utdallas.edu/~hamlen/bauman18ndss.pdf) / [Authors' Multiverse implementation](https://github.com/utds3lab/multiverse)
- **Ghidra**: [Official repository](https://github.com/NationalSecurityAgency/ghidra). This extension uses SLEIGH, P-code, PseudoDisassembler, and the Extension API.

This is an independently written Java implementation. The research C++/OCaml backend is not bundled.

## License

The repository's existing [MIT License](LICENSE) applies. Generated Gradle Wrapper files retain their original Apache-2.0 license; its [full text](licenses/Apache-2.0.txt) is included. Ghidra is a separate dependency.
