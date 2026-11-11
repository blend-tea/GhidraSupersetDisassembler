package amace.ui;

import amace.core.Candidate;
import amace.core.CandidateSelector;
import amace.core.Site;
import amace.ghidra.AnalysisReport;
import ghidra.app.services.GoToService;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.GhidraThreadedTablePanel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

final class AmaceResultsProvider extends ComponentProviderAdapter implements DomainObjectListener {
    private final AmacePlugin plugin;
    private final JPanel panel = new JPanel(new BorderLayout(0, 6));
    private final JPanel results = new JPanel(new BorderLayout());
    private final JLabel status = new JLabel("Run Tools → AMACE → Analyze and Apply.");
    private CandidateTableModel model;
    private GhidraThreadedTablePanel<CandidateRow> tablePanel;
    private GhidraTableFilterPanel<CandidateRow> filterPanel;
    private Program program;
    private long modificationNumber;
    private String summary = "";
    private boolean disposed;

    AmaceResultsProvider(AmacePlugin plugin, PluginTool tool) {
        super(tool, "AMACE Superset Candidates", plugin.getName());
        this.plugin = plugin;
        panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        panel.setPreferredSize(new Dimension(1100, 420));
        panel.add(status, BorderLayout.NORTH);
        panel.add(results, BorderLayout.CENTER);
        setTitle("AMACE Superset Candidates");
        addToTool();
    }

    @Override public JComponent getComponent() { return panel; }
    Program getProgram() { return program; }

    void setReport(Program reportProgram, AnalysisReport report, List<CandidateRow> rows) {
        clear();
        if (disposed || reportProgram.isClosed() || plugin.activeProgram() != reportProgram) return;
        if (!reportProgram.addConsumer(this)) return;
        program = reportProgram;
        modificationNumber = reportProgram.getModificationNumber();
        reportProgram.addListener(this);
        summary = report.summary();
        status.setText(summary);
        status.setToolTipText("Decode failures: " + report.decodeFailures() + "; unresolved edges: "
                + report.selection().unresolvedEdges().size() + "; deferred functions: "
                + report.selection().deferredFunctions().size());
        model = new CandidateTableModel(tool, reportProgram, rows);
        tablePanel = new GhidraThreadedTablePanel<>(model);
        var table = tablePanel.getTable();
        table.getAccessibleContext().setAccessibleName("AMACE superset instruction candidates");
        filterPanel = new GhidraTableFilterPanel<>(table, model);
        filterPanel.setAccessibleNamePrefix("AMACE candidates");
        table.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent event) {
                if (event.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(event)) navigate();
            }
        });
        filterPanel.addEnterListener(this::navigate);
        results.add(tablePanel, BorderLayout.CENTER);
        results.add(filterPanel, BorderLayout.SOUTH);
        model.reload();
        results.revalidate();
        results.repaint();
        setVisible(true);
    }

    private void navigate() {
        Program targetProgram = program;
        if (targetProgram == null || targetProgram.isClosed() || plugin.activeProgram() != targetProgram
                || filterPanel == null) return;
        CandidateRow row = filterPanel.getSelectedItem();
        var address = CandidateTableModel.address(row, targetProgram);
        var goTo = tool.getService(GoToService.class);
        if (address != null && goTo != null) goTo.goTo(address, targetProgram);
    }

    @Override public void domainObjectChanged(DomainObjectChangedEvent event) {
        Program source = program;
        if (source == null || event.getSource() != source) return;
        // Delayed notifications from the completed analysis have the same modification number.
        if (!source.isClosed() && source.getModificationNumber() == modificationNumber) return;
        SwingUtilities.invokeLater(() -> {
            if (!disposed && program == source) {
                status.setText("STALE — Program changed; rerun AMACE. " + summary);
                status.setToolTipText("Candidate facts describe the previous Program state.");
            }
        });
    }

    void clear() {
        if (program != null) {
            program.removeListener(this);
            program.release(this);
            program = null;
        }
        if (filterPanel != null) { filterPanel.dispose(); filterPanel = null; }
        if (tablePanel != null) { tablePanel.dispose(); tablePanel = null; }
        if (model != null) { model.dispose(); model = null; }
        results.removeAll();
        results.revalidate();
        results.repaint();
        summary = "";
        status.setText("Run Tools → AMACE → Analyze and Apply.");
        status.setToolTipText(null);
    }

    void dispose() {
        disposed = true;
        clear();
        removeFromTool();
    }

    @Override public void componentHidden() {
        // Keep the snapshot while hidden; closing/switching the Program releases it.
    }

    static List<CandidateRow> snapshotRows(AnalysisReport report) {
        Map<Site, List<String>> unresolved = new HashMap<>();
        for (var edge : report.selection().unresolvedEdges()) {
            if (edge.from() != null) unresolved.computeIfAbsent(edge.from(), ignored -> new ArrayList<>())
                    .add("Unresolved: " + edge.reason() + (edge.target() == null ? "" : " → " + edge.target()));
        }
        var rows = new ArrayList<CandidateRow>(report.candidates().size());
        for (Candidate candidate : report.candidates().values()) {
            var facts = report.analysis().facts().get(candidate.site());
            var decision = report.selection().decisions().get(candidate.site());
            String selection = decision == null ? "Not reachable" : reason(decision.reason());
            String detail = decision == null ? "" : decision.detail();
            if (facts != null && !facts.note().isBlank()) detail += "; " + facts.note();
            if (unresolved.containsKey(candidate.site())) detail += "; " + String.join("; ", unresolved.get(candidate.site()));
            String deferredFunction = report.selection().deferredFunctions().get(candidate.site());
            if (deferredFunction != null) detail += "; Function deferred: " + deferredFunction;
            if (!candidate.semantics().supported()) detail = "Unsupported semantics; " + detail;
            rows.add(new CandidateRow(candidate,
                    facts == null ? "unknown" : facts.pointerSummary(),
                    facts == null ? "unknown" : facts.stackSummary(),
                    facts == null ? "unknown" : facts.registerSummary(),
                    selection, detail));
        }
        return List.copyOf(rows);
    }

    private static String reason(CandidateSelector.Reason reason) {
        return switch (reason) {
            case ACCEPTED_TRUSTED -> "Accepted: trusted entry";
            case ACCEPTED_DIRECT_CALL -> "Accepted: direct call";
            case ACCEPTED_INFERRED -> "Accepted: AMACE inference";
            case BLOCKED -> "Deferred: existing definition / scope";
            case HIGHER_PRIORITY_OVERLAP -> "Deferred: stronger instruction overlaps";
            case AMBIGUOUS_OVERLAP -> "Deferred: equal-tier overlap";
            case UNREACHABLE_AFTER_CONFLICT -> "Deferred: path blocked by conflict";
            case NOT_REACHABLE -> "Not reachable from accepted roots";
        };
    }
}
