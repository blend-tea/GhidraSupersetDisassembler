// Analyze an imported ELF/PE or explicitly configured Raw Binary with AMACE.
// @category Analysis.AMACE
import amace.core.Abi;
import amace.core.Site;
import amace.ghidra.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import java.nio.file.Path;
import java.util.*;

public class RunAmace extends GhidraScript {
    @Override protected void run() throws Exception {
        // FlatProgramAPI starts a script transaction. Let the service own its
        // transaction so a failed/cancelled apply is immediately rolled back.
        end(true);
        Map<String,String> values = new LinkedHashMap<>();
        boolean apply = true;
        String[] args = getScriptArgs();
        Set<String> keys = Set.of("--abi", "--entry", "--start", "--end", "--report");
        for (int i=0; i<args.length; i++) {
            if (args[i].equals("--no-apply")) { apply = false; continue; }
            if (!keys.contains(args[i]) || i+1>=args.length) throw new IllegalArgumentException("Expected --abi, --entry, --start, --end, --report or --no-apply");
            if (values.put(args[i], args[++i]) != null) throw new IllegalArgumentException("Duplicate option: " + args[i-1]);
        }
        Abi abi = values.containsKey("--abi") ? Abi.valueOf(values.get("--abi").toUpperCase(Locale.ROOT)) : null;
        Set<Site> entries = new TreeSet<>();
        if (values.containsKey("--entry")) {
            for (String value : values.get("--entry").split(",")) entries.add(SupersetDecoder.site(parseAmaceAddress(value)));
        }
        AddressSet scope = AmaceAnalysisService.defaultScope(currentProgram);
        if (values.containsKey("--start") != values.containsKey("--end")) throw new IllegalArgumentException("Specify both --start and --end");
        if (values.containsKey("--start")) scope = new AddressSet(parseAmaceAddress(values.get("--start")), parseAmaceAddress(values.get("--end")));
        if (AmaceAnalysisService.isRaw(currentProgram) && (!values.containsKey("--start") || abi == null || entries.isEmpty())) {
            throw new IllegalArgumentException("Raw Binary requires --abi, --entry, --start and --end");
        }
        AnalysisReport report = new AmaceAnalysisService().run(currentProgram, scope,
            new AnalysisOptions(abi, entries, apply), monitor);
        println(report.summary());
        if (values.containsKey("--report")) {
            ReportWriter.write(report, Path.of(values.get("--report")));
            println("AMACE JSONL: " + values.get("--report"));
        }
    }

    private Address parseAmaceAddress(String value) {
        String normalized = value.trim().replaceFirst("^0[xX]", "");
        Address address = currentProgram.getAddressFactory().getAddress(normalized);
        if (address == null || !address.isMemoryAddress()) throw new IllegalArgumentException("Invalid memory address: " + value);
        return address;
    }
}
