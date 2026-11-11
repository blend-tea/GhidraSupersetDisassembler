package amace.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Dependency-free regression tests; execute with java -ea amace.core.CandidateSelectorTest. */
public final class CandidateSelectorTest {
    private static int assertions;
    private static final Runnable CANCEL = () -> {};

    public static void main(String[] args) {
        trustedThenCallClosure();
        equalPriorityRootsAbstain();
        strongerInstructionWins();
        preservePrefixAtAmbiguousBranch();
        pruneRejectedCallerCallee();
        orderInvariant();
        deferSharedTailFunctions();
        speculativeEntryDoesNotTruncateTrustedBody();
        callNextIsNotFunction();
        noReturnCutsFallthrough();
        indirectTransfersRemainUnresolved();
        blockedDefinitionsRemainBlocked();
        strongerAmbiguityCannotBeFilledByWeakerRoot();
        addressSpacesAndUnsignedOffsets();
        cancellationPropagates();
        lowerTierSharedBodyDefers();
        System.out.println("CandidateSelectorTest: " + assertions + " assertions passed");
    }

    private static void trustedThenCallClosure() {
        var result = run(map(call(0, 5, 16, 5), ret(5), call(16, 5, 32, 21), ret(21), ret(32)), Set.of(s(0)));
        eq(result.accepted(), sites(0,5,16,21,32), "all reachable instructions");
        eq(result.decisions().get(s(0)).tier(), 1, "trusted caller tier");
        eq(result.decisions().get(s(16)).tier(), 2, "direct callee tier");
        eq(result.decisions().get(s(32)).tier(), 2, "transitive callee tier");
        eq(result.entryTiers(), Map.of(s(0),1,s(16),2,s(32),2), "call entries");
        eq(result.functionBodies().get(s(0)), sites(0,5), "caller excludes callee");
    }

    private static void equalPriorityRootsAbstain() {
        var result = run(map(normal(0,5,5), normal(2,3,5), ret(5)), sites(0,2));
        eq(result.accepted(), Set.of(), "equal root overlap chooses neither");
        reason(result,0,CandidateSelector.Reason.AMBIGUOUS_OVERLAP);
        reason(result,2,CandidateSelector.Reason.AMBIGUOUS_OVERLAP);
        reason(result,5,CandidateSelector.Reason.UNREACHABLE_AFTER_CONFLICT);
    }

    private static void strongerInstructionWins() {
        var result = select(map(node(0,5,FlowKind.RETURN,List.of(),null), ret(2)), sites(0), sites(2), Set.of(), Set.of());
        eq(result.accepted(), sites(0), "inferred interior cannot replace trusted instruction");
        reason(result,2,CandidateSelector.Reason.HIGHER_PRIORITY_OVERLAP);
    }

    private static void preservePrefixAtAmbiguousBranch() {
        var result = run(map(normal(0,1,1), branch(1,2,2,3), ret(2), ret(3)), sites(0));
        eq(result.accepted(), sites(0), "uncontested prefix remains");
        reason(result,1,CandidateSelector.Reason.AMBIGUOUS_OVERLAP);
        reason(result,2,CandidateSelector.Reason.AMBIGUOUS_OVERLAP);
        reason(result,3,CandidateSelector.Reason.UNREACHABLE_AFTER_CONFLICT);
        check(result.unresolvedEdges().stream().anyMatch(e -> s(0).equals(e.from()) && s(1).equals(e.target())), "prefix reports unresolved successor");
    }

    private static void pruneRejectedCallerCallee() {
        var result = run(map(call(0,5,10,5),ret(5),branch(10,2,11,12),call(11,5,30,16),ret(12),ret(16),ret(30)), sites(0));
        eq(result.accepted(), sites(0,5), "rejected second-tier caller does not seed callee");
        reason(result,30,CandidateSelector.Reason.UNREACHABLE_AFTER_CONFLICT);
        check(!result.entryTiers().containsKey(s(30)), "orphan callee has no function entry");
    }

    private static void orderInvariant() {
        var nodes = new ArrayList<>(List.of(call(0,5,10,5),ret(5),branch(10,2,11,12),call(11,5,30,16),ret(12),ret(16),ret(30),ret(50)));
        var first = select(map(nodes.toArray(Candidate[]::new)), sites(0), sites(50), Set.of(), Set.of());
        Collections.reverse(nodes);
        var second = select(map(nodes.toArray(Candidate[]::new)), new LinkedHashSet<>(List.of(s(0))), new LinkedHashSet<>(List.of(s(50))), Set.of(), Set.of());
        eq(first,second,"candidate iteration order cannot choose winner");
        var roots = new LinkedHashSet<>(List.of(s(0),s(2)));
        var equal = map(normal(0,5,5),normal(2,3,5),ret(5));
        var a = run(equal,roots);
        roots = new LinkedHashSet<>(List.of(s(2),s(0)));
        eq(a,run(equal,roots),"root iteration order cannot choose winner");
    }

    private static void deferSharedTailFunctions() {
        var result = run(map(jump(0,8),jump(4,8),ret(8)),sites(0,4));
        eq(result.accepted(),sites(0,4,8),"shared tail instructions remain accepted");
        eq(result.functionBodies(),Map.of(),"equally ranked shared-tail functions both deferred");
        eq(result.deferredFunctions().keySet(),sites(0,4),"both function hypotheses retained");
    }

    private static void speculativeEntryDoesNotTruncateTrustedBody() {
        var result = select(map(normal(0,1,1),normal(1,1,2),ret(2)),sites(0),sites(1),Set.of(),Set.of());
        eq(result.functionBodies().get(s(0)),sites(0,1,2),"weaker entry does not truncate stronger body");
        check(result.deferredFunctions().containsKey(s(1)),"interior speculative function deferred");
    }

    private static void callNextIsNotFunction() {
        var result = run(map(call(0,5,5,5),ret(5)),sites(0));
        eq(result.accepted(),sites(0,5),"call-next retains following instruction");
        eq(result.entryTiers(),Map.of(s(0),1),"call-next creates no independent function");
    }

    private static void noReturnCutsFallthrough() {
        var result = select(map(call(0,5,10,5),ret(5),node(10,1,FlowKind.HALT,List.of(),null)),sites(0),Set.of(),sites(0),Set.of());
        eq(result.accepted(),sites(0,10),"noreturn call cuts fallthrough but retains callee");
        eq(result.functionBodies().get(s(0)),sites(0),"noreturn caller body stops at call");
    }

    private static void indirectTransfersRemainUnresolved() {
        var result = run(map(node(0,2,FlowKind.INDIRECT_CALL,List.of(),s(2)),ret(2),node(4,2,FlowKind.INDIRECT_JUMP,List.of(),null)),sites(0,4));
        eq(result.accepted(),sites(0,2,4),"indirect call keeps fallthrough");
        eq(result.unresolvedEdges().stream().filter(e -> e.target()==null).count(),2L,"indirect transfers remain explicit");
    }

    private static void blockedDefinitionsRemainBlocked() {
        var result = select(map(normal(0,1,1),ret(1)),sites(0),Set.of(),Set.of(),sites(1));
        eq(result.accepted(),sites(0),"existing definition blocks traversal");
        reason(result,1,CandidateSelector.Reason.BLOCKED);
    }

    private static void strongerAmbiguityCannotBeFilledByWeakerRoot() {
        var result = select(map(normal(0,3,3),ret(1),ret(2),ret(3)),sites(0,2),sites(1),Set.of(),Set.of());
        eq(result.accepted(),Set.of(),"weaker roots cannot fill disputed trusted bytes");
        reason(result,1,CandidateSelector.Reason.HIGHER_PRIORITY_OVERLAP);
    }

    private static void addressSpacesAndUnsignedOffsets() {
        Candidate ram = ret(0);
        Candidate other = new Candidate(new Site("other",0),new byte[1],"ret","",FlowKind.RETURN,List.of(),null,Semantics.identity());
        long high = 0x8000000000000000L;
        Candidate unsigned = node(high,1,FlowKind.RETURN,List.of(),null);
        var result = run(map(ram,other,unsigned),Set.of(ram.site(),other.site(),unsigned.site()));
        eq(result.accepted(),Set.of(ram.site(),other.site(),unsigned.site()),"space identity and unsigned addresses preserved");
    }

    private static void cancellationPropagates() {
        boolean cancelled = false;
        try {
            new CandidateSelector().select(map(ret(0)),sites(0),Set.of(),Set.of(),Set.of(),() -> { throw new IllegalStateException("cancel"); });
        } catch (IllegalStateException expected) { cancelled = expected.getMessage().equals("cancel"); }
        check(cancelled,"cancellation propagates instead of returning partial result");
    }

    private static void lowerTierSharedBodyDefers() {
        var result = run(map(jump(0,20),call(30,5,10,35),ret(35),jump(10,20),ret(20)),sites(0,30));
        eq(result.functionBodies().get(s(0)),sites(0,20),"trusted shared-tail function retained");
        check(result.deferredFunctions().containsKey(s(10)),"lower-priority shared-tail function deferred");
    }

    private static CandidateSelector.Selection run(Map<Site,Candidate> nodes,Set<Site> roots) {
        return select(nodes,roots,Set.of(),Set.of(),Set.of());
    }
    private static CandidateSelector.Selection select(Map<Site,Candidate> nodes,Set<Site> roots,Set<Site> inferred,Set<Site> noreturn,Set<Site> blocked) {
        return new CandidateSelector().select(nodes,roots,inferred,noreturn,blocked,CANCEL);
    }
    private static Site s(long address) { return new Site("ram",address); }
    private static Set<Site> sites(long... values) {
        var sites = new LinkedHashSet<Site>();
        for(long value:values) sites.add(s(value));
        return sites;
    }
    private static Map<Site,Candidate> map(Candidate... values) {
        var result = new LinkedHashMap<Site,Candidate>();
        for(Candidate candidate:values) result.put(candidate.site(),candidate);
        return result;
    }
    private static Candidate normal(long start,int length,long next) { return node(start,length,FlowKind.NORMAL,List.of(),s(next)); }
    private static Candidate ret(long start) { return node(start,1,FlowKind.RETURN,List.of(),null); }
    private static Candidate jump(long start,long target) { return node(start,1,FlowKind.JUMP,List.of(s(target)),null); }
    private static Candidate branch(long start,int length,long target,long next) { return node(start,length,FlowKind.CONDITIONAL_JUMP,List.of(s(target)),s(next)); }
    private static Candidate call(long start,int length,long target,long next) { return node(start,length,FlowKind.CALL,List.of(s(target)),s(next)); }
    private static Candidate node(long start,int length,FlowKind flow,List<Site> targets,Site fallthrough) {
        return new Candidate(s(start),new byte[length],flow.name(),"",flow,targets,fallthrough,Semantics.identity());
    }
    private static void reason(CandidateSelector.Selection result,long address,CandidateSelector.Reason expected) {
        eq(result.decisions().get(s(address)).reason(),expected,"candidate reason at "+address);
    }
    private static void check(boolean condition,String message) {
        assertions++;
        if(!condition) throw new AssertionError(message);
    }
    private static void eq(Object actual,Object expected,String message) {
        assertions++;
        if(!java.util.Objects.equals(actual,expected)) throw new AssertionError(message+" expected="+expected+" actual="+actual);
    }
}
