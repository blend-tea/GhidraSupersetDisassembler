package amace.ghidra;

import amace.core.*;
import java.util.List;
import java.util.Map;

/** Complete superset plus the conservative Listing projection from one run. */
public record AnalysisReport(Map<Site,Candidate> candidates, AmaceEngine.Analysis analysis,
        CandidateSelector.Selection selection, Map<String,Long> decodeFailures, long attempted,
        int createdInstructions, int createdFunctions, List<String> conflicts, boolean applied,
        String programName) {
    public AnalysisReport {
        candidates = Map.copyOf(candidates); decodeFailures = Map.copyOf(decodeFailures);
        conflicts = List.copyOf(conflicts);
    }
    public String summary() {
        return String.format("%s: %d offsets, %d candidates, %d selected, %d new instructions, %d new functions, %d conflicts",
                programName, attempted, candidates.size(), selection.accepted().size(),
                createdInstructions, createdFunctions, conflicts.size());
    }
}
