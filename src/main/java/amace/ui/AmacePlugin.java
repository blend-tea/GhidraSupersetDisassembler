package amace.ui;

import amace.ghidra.AmaceAnalysisService;
import amace.ghidra.AnalysisException;
import amace.ghidra.AnalysisOptions;
import amace.ghidra.AnalysisReport;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.swing.SwingUtilities;

@PluginInfo(status = PluginStatus.RELEASED, packageName = CorePluginPackage.NAME,
        category = PluginCategoryNames.ANALYSIS,
        shortDescription = "AMACE Superset Disassembly",
        description = "Decodes every x86 byte offset, runs backward AMACE analyses, and conservatively applies instructions and functions.",
        servicesRequired = { GoToService.class })
public final class AmacePlugin extends ProgramPlugin {
    private final DockingAction analyzeAction;
    private final AmaceResultsProvider results;
    private final ExecutorService executor = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "AMACE analysis");
        thread.setDaemon(true);
        return thread;
    });
    private volatile TaskMonitor runningMonitor;
    private volatile Program runningProgram;
    private volatile boolean disposed;

    public AmacePlugin(PluginTool tool) {
        super(tool);
        results = new AmaceResultsProvider(this, tool);
        analyzeAction = new DockingAction("Analyze and Apply", getName()) {
            @Override public void actionPerformed(ActionContext context) { analyze(); }
            @Override public boolean isEnabledForContext(ActionContext context) {
                return !disposed && currentProgram != null && !currentProgram.isClosed() && runningMonitor == null;
            }
        };
        analyzeAction.setMenuBarData(new MenuData(new String[] { "Tools", "AMACE", "Analyze and Apply" }));
        analyzeAction.setDescription("Run AMACE before standard autoanalysis; preserve competing candidates in the results table.");
        analyzeAction.setEnabled(false);
        tool.addAction(analyzeAction);
    }

    Program activeProgram() { return currentProgram; }

    private void analyze() {
        Program program = currentProgram;
        if (program == null || program.isClosed() || runningMonitor != null) return;
        var scope = currentSelection != null && !currentSelection.isEmpty()
                ? new AddressSet(currentSelection) : AmaceAnalysisService.defaultScope(program);
        AnalysisOptions options = AnalysisOptions.defaults();
        if (AmaceAnalysisService.isRaw(program)) {
            var dialog = new RawOptionsDialog(program, scope);
            tool.showDialog(dialog);
            var request = dialog.getRequest();
            if (request == null) return;
            scope = request.scope();
            options = request.options();
        }
        if (scope.isEmpty()) {
            Msg.showInfo(this, results.getComponent(), "AMACE", "Select initialized memory, or import a program with executable memory.");
            return;
        }
        startAnalysis(program, scope, options);
    }

    /** AutoAnalysisManager owns the sole modal progress window. Never wrap it in TaskLauncher. */
    void startAnalysis(Program program, AddressSet scope, AnalysisOptions options) {
        if (!SwingUtilities.isEventDispatchThread()) throw new IllegalStateException("Start AMACE on the EDT");
        if (disposed || runningMonitor != null || program.isClosed()) return;
        final AddressSet capturedScope = new AddressSet(scope);
        final AnalysisOptions capturedOptions = options;
        final Object consumer = new Object();
        if (!program.addConsumer(consumer)) return;
        runningProgram = program;
        TaskMonitor monitor = new TaskMonitorAdapter(true);
        runningMonitor = monitor;
        updateEnabled();
        try {
            executor.execute(() -> {
                AnalysisReport report = null;
                List<CandidateRow> rows = null;
                Exception failure = null;
                boolean cancelled = false;
                try {
                    report = new AmaceAnalysisService().run(program, capturedScope, capturedOptions, monitor);
                    monitor.setMessage("Preparing candidate table");
                    rows = AmaceResultsProvider.snapshotRows(report);
                }
                catch (CancelledException ex) { cancelled = true; }
                catch (AnalysisException | RuntimeException ex) { failure = ex; }
                final AnalysisReport completedReport = report;
                final List<CandidateRow> completedRows = rows;
                final Exception completedFailure = failure;
                final boolean wasCancelled = cancelled;
                SwingUtilities.invokeLater(() -> {
                    try {
                        if (!disposed && currentProgram == program && !program.isClosed()) {
                            if (completedFailure != null) {
                                Msg.showError(AmacePlugin.this, results.getComponent(), "AMACE analysis failed",
                                        completedFailure.getMessage(), completedFailure);
                            }
                            else if (completedReport != null) results.setReport(program, completedReport, completedRows);
                            else if (wasCancelled) tool.setStatusInfo("AMACE analysis cancelled; no analysis changes applied.");
                        }
                    }
                    finally {
                        program.release(consumer);
                        runningMonitor = null;
                        runningProgram = null;
                        if (!disposed) updateEnabled();
                    }
                });
            });
        }
        catch (RuntimeException ex) {
            runningMonitor = null; runningProgram = null;
            program.release(consumer);
            updateEnabled();
            throw ex;
        }
    }

    private void updateEnabled() {
        analyzeAction.setEnabled(!disposed && currentProgram != null && !currentProgram.isClosed() && runningMonitor == null);
        tool.contextChanged(null);
    }

    @Override protected void programActivated(Program program) {
        if (results != null && results.getProgram() != program) results.clear();
        if (analyzeAction != null) updateEnabled();
    }

    @Override protected void programDeactivated(Program program) {
        if (results != null) results.clear();
    }

    @Override protected void programClosed(Program program) {
        if (runningProgram == program && runningMonitor != null) runningMonitor.cancel();
        if (results != null && results.getProgram() == program) results.clear();
        if (analyzeAction != null) updateEnabled();
    }

    @Override protected void dispose() {
        disposed = true;
        if (runningMonitor != null) runningMonitor.cancel();
        executor.shutdown();
        results.dispose();
        tool.removeAction(analyzeAction);
        super.dispose();
    }
}
