package amace.ghidra;

import amace.core.Abi;
import amace.core.Site;
import java.util.Set;

/** Null ABI requests detection for ELF/PE. Raw inputs require an explicit ABI and entry. */
public record AnalysisOptions(Abi abi, Set<Site> trustedEntries, boolean apply) {
    public AnalysisOptions { trustedEntries = Set.copyOf(trustedEntries); }
    public static AnalysisOptions defaults() { return new AnalysisOptions(null, Set.of(), true); }
}
