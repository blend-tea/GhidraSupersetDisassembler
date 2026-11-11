package amace.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import static amace.core.AbstractDomains.*;

/** Paper-domain golden examples, runnable without Ghidra or a test framework. */
public final class DomainTest {
    private static void check(boolean ok, String message) { if (!ok) throw new AssertionError(message); }
    public static void main(String[] args) {
        depthMerges(); depthBoundAndOrder(); depthTransfers(); restoreMerges(); majorityAndBounds();
        System.out.println("DomainTest: all checks passed");
    }
    private static void depthMerges() {
        var result = mergeDepths(List.of(Depth.concrete(0, 16, 2), Depth.concrete(0, 48, 1),
            Depth.concrete(16, 48, 1)), 10);
        check(result.equals(List.of(Depth.concrete(0, 48, 3), Depth.concrete(16, 48, 1))), "Table 3 union and equal-depth merge");
        check(mergeDepths(List.of(Depth.zero(), Depth.unknown()), 1).getFirst().kind() == DepthKind.UNKNOWN,
            "a one-slot cap does not manufacture concrete evidence");
    }
    private static void depthBoundAndOrder() {
        var input = new ArrayList<Depth>();
        for (int n = 0; n < 20; n++) input.add(Depth.concrete(n * 1000, n * 1000, n + 1));
        input.add(Depth.unknown());
        var expected = mergeDepths(input, 10);
        check(expected.size() == 10, "k caps tuple count, not depth value");
        check(expected.stream().anyMatch(d -> d.value() == 19000), "large numeric depth retained");
        check(expected.stream().anyMatch(d -> d.kind() == DepthKind.AGGREGATE), "least frequent depths aggregated");
        for (int seed = 0; seed < 20; seed++) {
            Collections.shuffle(input, new Random(seed));
            check(mergeDepths(input, 10).equals(expected), "depth merge independent of iteration order");
        }
    }
    private static void depthTransfers() {
        var onePop = shiftDepths(List.of(Depth.zero()), 8);
        check(onePop.equals(List.of(Depth.concrete(8, 8, 1))), "pop increases backward depth");
        var push = shiftDepths(List.of(Depth.concrete(48, 48, 2)), -32);
        check(push.equals(List.of(Depth.concrete(16, 48, 2))), "maximum tracks the path, not only current depth");
        check(shiftDepths(List.of(Depth.concrete(Long.MAX_VALUE, Long.MAX_VALUE, 1)), 1).getFirst().kind() == DepthKind.UNKNOWN,
            "signed depth overflow is unknown");
        check(mergeDepths(List.of(Depth.concrete(0, 0, Long.MAX_VALUE), Depth.zero()), 10).getFirst().count() == Long.MAX_VALUE,
            "counts saturate");
    }
    private static void restoreMerges() {
        var a = new Restore(SourceKind.REGISTER, "rbx", new StackSlot("rsp", -8, false), "rbx", 1);
        var b = new Restore(SourceKind.REGISTER, "rbx", new StackSlot("rsp", -16, false), "rbx", 2);
        var c = Restore.identity("rbp");
        var result = mergeRestores(List.of(a, b, c), 1);
        check(result.size() == 2, "restore cap is per destination");
        Restore merged = result.stream().filter(r -> r.destination().equals("rbx")).findFirst().orElseThrow();
        check(merged.slot().aggregate() && merged.count() == 3 && !merged.mismatch(), "same-source stack offsets aggregate before count loss");
        check(mergeRestores(List.of(a, a), 10).getFirst().count() == 2, "identical restores merge counts");
    }
    private static void majorityAndBounds() {
        var good = Restore.identity("rbx");
        var wrong = new Restore(SourceKind.REGISTER, "rsi", null, "rbx", 1);
        check(registersCompatible(List.of(good, wrong)), "a tie is not strict majority mismatch");
        check(!registersCompatible(List.of(good, new Restore(SourceKind.STACK, "", new StackSlot("rsp", 0, false), "rbx", 2))),
            "unmatched restore from stack counts as mismatch");
        check(registersCompatible(List.of(Restore.unknown("rbx", 4), wrong)), "unknown is not mismatch evidence");
        check(registersCompatible(List.of(new Restore(SourceKind.REGISTER, "rbx", null, "rbx", Long.MAX_VALUE),
            new Restore(SourceKind.REGISTER, "rsi", null, "rbx", Long.MAX_VALUE))),
            "saturated observation counts do not turn a tie into mismatch");
        var many = new ArrayList<Restore>();
        for (int n = 0; n < 25; n++) many.add(new Restore(SourceKind.REGISTER, "r" + n, null, "rbx", n + 1));
        many.add(Restore.unknown("rbx", 1));
        var expected = mergeRestores(many, 10);
        check(expected.size() == 10, "restore observations bounded");
        check(expected.stream().anyMatch(r -> r.kind() == SourceKind.AGGREGATE), "incompatible low-count sources aggregate to mismatch");
        for (int seed = 0; seed < 20; seed++) {
            Collections.shuffle(many, new Random(seed));
            check(mergeRestores(many, 10).equals(expected), "restore merge independent of iteration order");
        }
    }
}
