package amace.core;

/** Standalone runner so semantic tests need no external test-framework download. */
public final class AllCoreTests {
    public static void main(String[] args) throws Exception {
        DomainTest.main(args);
        CandidateSelectorTest.main(args);
        EngineTest.main(args);
        System.out.println("All AMACE core tests passed.");
    }
}
