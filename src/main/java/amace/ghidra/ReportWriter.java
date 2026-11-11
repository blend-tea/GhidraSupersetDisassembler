package amace.ghidra;

import amace.core.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/** Streaming JSON-lines report: the first line is metadata, followed by every candidate. */
public final class ReportWriter {
    private ReportWriter() {}
    public static void write(AnalysisReport report, Path destination) throws IOException {
        Gson gson = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();
        try (BufferedWriter writer = Files.newBufferedWriter(destination, StandardCharsets.UTF_8)) {
            Map<String,Object> metadata = new LinkedHashMap<>();
            metadata.put("kind", "amace-report"); metadata.put("schemaVersion", 1);
            metadata.put("program", report.programName()); metadata.put("summary", report.summary());
            metadata.put("attempted", report.attempted()); metadata.put("decodeFailures", new TreeMap<>(report.decodeFailures()));
            metadata.put("applied", report.applied()); metadata.put("conflicts", report.conflicts());
            writer.write(gson.toJson(metadata)); writer.newLine();
            for (var entry : new TreeMap<>(report.candidates()).entrySet()) {
                Site site = entry.getKey(); Candidate candidate = entry.getValue();
                Map<String,Object> row = new LinkedHashMap<>();
                row.put("kind", "candidate"); row.put("addressSpace", site.space());
                row.put("offset", Long.toUnsignedString(site.offset(),16));
                row.put("bytes", HexFormat.of().formatHex(candidate.bytes()));
                row.put("mnemonic", candidate.mnemonic()); row.put("operands", candidate.operands());
                row.put("flow", candidate.flow()); row.put("semanticsSupported", candidate.semantics().supported());
                row.put("facts", report.analysis().facts().get(site));
                row.put("decision", report.selection().decisions().get(site));
                row.put("functionTier", report.selection().entryTiers().get(site));
                row.put("deferredFunction", report.selection().deferredFunctions().get(site));
                writer.write(gson.toJson(row)); writer.newLine();
            }
            for (var edge : report.selection().unresolvedEdges()) {
                writer.write(gson.toJson(Map.of("kind", "unresolved-edge", "edge", edge))); writer.newLine();
            }
        }
    }
}
