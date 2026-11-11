package amace.ui;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.GhidraProgramTableModel;
import ghidra.util.task.TaskMonitor;
import java.util.HexFormat;
import java.util.List;
import java.util.function.Function;

final class CandidateTableModel extends GhidraProgramTableModel<CandidateRow> {
    private final List<CandidateRow> rows;

    CandidateTableModel(ServiceProvider services, Program program, List<CandidateRow> rows) {
        super("AMACE Superset Candidates", services, program, TaskMonitor.DUMMY);
        this.rows = List.copyOf(rows);
    }

    @Override protected void doLoad(Accumulator<CandidateRow> accumulator, TaskMonitor monitor)
            throws CancelledException {
        if (rows == null) return;
        monitor.initialize(rows.size());
        for (CandidateRow row : rows) {
            monitor.checkCancelled();
            accumulator.add(row);
            monitor.incrementProgress(1);
        }
    }

    @Override protected TableColumnDescriptor<CandidateRow> createTableColumnDescriptor() {
        var columns = new TableColumnDescriptor<CandidateRow>();
        columns.addVisibleColumn(new AddressColumn(), 1, true);
        columns.addVisibleColumn(new TextColumn("Bytes", r -> HexFormat.ofDelimiter(" ").formatHex(r.candidate().bytes()), 190));
        columns.addVisibleColumn(new TextColumn("Instruction", r -> r.candidate().mnemonic() + " " + r.candidate().operands(), 240));
        columns.addVisibleColumn(new TextColumn("Pointer definedness", CandidateRow::pointerFacts, 180));
        columns.addVisibleColumn(new TextColumn("Stack depth", CandidateRow::stackFacts, 200));
        columns.addVisibleColumn(new TextColumn("Callee-saved registers", CandidateRow::registerFacts, 200));
        columns.addVisibleColumn(new TextColumn("Selection", CandidateRow::selection, 260));
        columns.addVisibleColumn(new TextColumn("Details", CandidateRow::details, 300));
        return columns;
    }

    @Override public Address getAddress(int modelRow) {
        return address(getRowObject(modelRow), program);
    }

    static Address address(CandidateRow row, Program program) {
        if (row == null || program == null) return null;
        var site = row.candidate().site();
        var space = program.getAddressFactory().getAddressSpace(site.space());
        return space == null ? null : space.getAddress(site.offset());
    }

    private static final class AddressColumn extends AbstractDynamicTableColumn<CandidateRow, Address, Program> {
        @Override public String getColumnName() { return "Address"; }
        @Override public int getColumnPreferredWidth() { return 140; }
        @Override public Address getValue(CandidateRow row, Settings settings, Program program,
                ServiceProvider services) { return address(row, program); }
    }

    private static final class TextColumn extends AbstractDynamicTableColumn<CandidateRow, String, Program> {
        private final String name;
        private final Function<CandidateRow, String> value;
        private final int width;
        TextColumn(String name, Function<CandidateRow, String> value, int width) {
            this.name = name; this.value = value; this.width = width;
        }
        @Override public String getColumnName() { return name; }
        @Override public int getColumnPreferredWidth() { return width; }
        @Override public String getValue(CandidateRow row, Settings settings, Program program,
                ServiceProvider services) { return value.apply(row); }
    }
}
