package amace.ui;

import amace.core.Abi;
import amace.core.Site;
import amace.ghidra.AnalysisOptions;
import docking.DialogComponentProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.util.Arrays;
import java.util.Set;
import javax.swing.BorderFactory;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

/** Raw binaries have no trustworthy loader entry or ABI: both must be explicit. */
final class RawOptionsDialog extends DialogComponentProvider {
    record Request(AddressSet scope, AnalysisOptions options) {}

    private final Program program;
    private final JTextField entry = new JTextField(24);
    private final JTextField start = new JTextField(24);
    private final JTextField end = new JTextField(24);
    private final JComboBox<Abi> abi;
    private Request request;

    RawOptionsDialog(Program program, AddressSetView scope) {
        super("AMACE — Raw Binary", true);
        this.program = program;
        int bits = program.getLanguage().getLanguageDescription().getSize();
        abi = new JComboBox<>(Arrays.stream(Abi.values()).filter(a -> a.bits() == bits)
                .toArray(Abi[]::new));
        if (!scope.isEmpty()) {
            start.setText(scope.getMinAddress().toString());
            end.setText(scope.getMaxAddress().toString());
        }
        var fields = new JPanel(new GridLayout(4, 2, 8, 8));
        fields.add(new JLabel("Entry address (hex):")); fields.add(entry);
        fields.add(new JLabel("First address (inclusive):")); fields.add(start);
        fields.add(new JLabel("Last address (inclusive):")); fields.add(end);
        fields.add(new JLabel("Calling convention / ABI:")); fields.add(abi);
        var panel = new JPanel(new BorderLayout(0, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        panel.add(new JLabel("Specify the entry, initialized memory range, and ABI."), BorderLayout.NORTH);
        panel.add(fields, BorderLayout.CENTER);
        panel.add(new JLabel("Uses the language and image base selected during import."), BorderLayout.SOUTH);
        addWorkPanel(panel);
        addOKButton();
        addCancelButton();
        setOkButtonText("Analyze and Apply");
    }

    Request getRequest() { return request; }

    @Override protected void okCallback() {
        try {
            Address first = parse(start, "First address");
            Address last = parse(end, "Last address");
            Address entryAddress = parse(entry, "Entry address");
            if (!first.getAddressSpace().equals(last.getAddressSpace()) || first.compareTo(last) > 0) {
                throw new IllegalArgumentException("The range must be ordered within one address space.");
            }
            var scope = new AddressSet(first, last)
                    .intersect(program.getMemory().getLoadedAndInitializedAddressSet());
            if (scope.isEmpty()) throw new IllegalArgumentException("The range contains no initialized loaded memory.");
            if (!scope.contains(entryAddress)) throw new IllegalArgumentException("The entry must be inside initialized memory in the range.");
            Abi selectedAbi = (Abi) abi.getSelectedItem();
            if (selectedAbi == null) throw new IllegalArgumentException("A 32-bit or 64-bit x86 language is required.");
            request = new Request(scope, new AnalysisOptions(selectedAbi,
                    Set.of(new Site(entryAddress.getAddressSpace().getName(), entryAddress.getOffset())), true));
            close();
        }
        catch (IllegalArgumentException ex) {
            setStatusText(ex.getMessage());
        }
    }

    private Address parse(JTextField field, String label) {
        String text = field.getText().trim().replaceFirst("^0[xX]", "");
        Address address = text.isEmpty() ? null : program.getAddressFactory().getAddress(text);
        if (address == null || !address.isMemoryAddress()) {
            throw new IllegalArgumentException(label + " is not a valid memory address.");
        }
        return address;
    }
}
