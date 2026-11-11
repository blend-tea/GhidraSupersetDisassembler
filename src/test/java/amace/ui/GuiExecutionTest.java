package amace.ui;

import ghidra.GhidraApplicationLayout;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.framework.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.lang.reflect.*;
import java.util.concurrent.atomic.*;
import javax.swing.SwingUtilities;

/** Real GUI execution regression: one modal owner, reentry guard, completion and cancellation. */
public final class GuiExecutionTest {
    static final AtomicInteger opened = new AtomicInteger(), visible = new AtomicInteger(), peak = new AtomicInteger();
    static class TestTool extends PluginTool {
        TestTool() { super(null,null,null,"AMACE execution regression",true,true,false); }
        void closeTest() { super.dispose(); }
    }
    static Object running(AmacePlugin plugin) throws Exception {
        Field field;
        try { field = AmacePlugin.class.getDeclaredField("runningMonitor"); }
        catch (NoSuchFieldException e) { field = AmacePlugin.class.getDeclaredField("runningTask"); }
        field.setAccessible(true); return field.get(plugin);
    }
    static void start(AmacePlugin plugin) throws Exception {
        Method method = AmacePlugin.class.getDeclaredMethod("analyze");
        method.setAccessible(true); method.invoke(plugin);
    }
    public static void main(String[] args) throws Exception {
        try { run(args); System.out.println("GUI_EXECUTION_PASS: one modal window per run, reentry blocked, completion and cancellation"); System.exit(0); }
        catch (Throwable error) { error.printStackTrace(); System.exit(1); }
    }
    static void run(String[] args) throws Exception {
        var config = new GhidraApplicationConfiguration(); config.setShowSplashScreen(false);
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),config);
        Toolkit.getDefaultToolkit().addAWTEventListener(event -> {
            WindowEvent e = (WindowEvent) event;
            if (!(e.getWindow() instanceof Dialog dialog) || !dialog.getTitle().contains("AMACE Superset Analysis")) return;
            if (e.getID() == WindowEvent.WINDOW_OPENED) {
                opened.incrementAndGet(); peak.accumulateAndGet(visible.incrementAndGet(),Math::max);
            }
            if (e.getID() == WindowEvent.WINDOW_CLOSED) visible.decrementAndGet();
        }, AWTEvent.WINDOW_EVENT_MASK);
        var tool = new AtomicReference<TestTool>(); var plugin = new AtomicReference<AmacePlugin>();
        SwingUtilities.invokeAndWait(() -> { tool.set(new TestTool()); plugin.set(new AmacePlugin(tool.get())); });
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
        try {
            for (boolean cancel : new boolean[]{false,true}) {
                Object consumer = new Object();
                ProgramDB program = new ProgramDB("GUI fixture",language,language.getCompilerSpecByID(new CompilerSpecID("gcc")),consumer);
                try {
                    var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                    int tx = program.startTransaction("fixture");
                    try {
                        var block = program.getMemory().createInitializedBlock("code",address,4096,(byte)0x90,TaskMonitor.DUMMY,false);
                        block.setExecute(true); program.getMemory().setByte(address.add(4095),(byte)0xc3);
                        program.setExecutableFormat("Executable and Linking Format (ELF)");
                        program.getSymbolTable().addExternalEntryPoint(address);
                    } finally { program.endTransaction(tx,true); }
                    int before = opened.get(); peak.set(0);
                    SwingUtilities.invokeAndWait(() -> {
                        try {
                            plugin.get().processEvent(new ProgramActivatedPluginEvent("test",program));
                            start(plugin.get()); start(plugin.get());
                        } catch (Exception e) { throw new RuntimeException(e); }
                    });
                    long deadline = System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(60);
                    boolean requestedCancel = false;
                    while (running(plugin.get()) != null && System.nanoTime()<deadline) {
                        if (cancel && !requestedCancel && opened.get()>before) {
                            Object monitor = running(plugin.get());
                            if (monitor instanceof TaskMonitor m) { m.cancel(); requestedCancel=true; }
                        }
                        Thread.sleep(25);
                    }
                    SwingUtilities.invokeAndWait(() -> {});
                    if (running(plugin.get()) != null) throw new AssertionError("GUI execution did not finish");
                    if (opened.get()-before != 1 || peak.get()!=1) throw new AssertionError("Competing/repeated modal windows: opened="+(opened.get()-before)+", peak="+peak.get());
                    long instructions=program.getListing().getNumInstructions();
                    if (!cancel && instructions!=4096) throw new AssertionError("Analysis did not apply complete fixture: "+instructions);
                    if (cancel && (!requestedCancel || instructions!=0)) throw new AssertionError("Cancellation did not preserve Listing");
                    System.out.println("GUI run cancel="+cancel+": modal opens=1, instructions="+instructions);
                } finally { program.release(consumer); }
            }
        } finally { SwingUtilities.invokeAndWait(() -> { plugin.get().dispose(); tool.get().closeTest(); }); }
    }
}
