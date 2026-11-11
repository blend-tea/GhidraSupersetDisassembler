package amace.core;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Conservative projection of the overlapping superset into a conventional Listing.
 * This is an integration policy, not an additional claim made by the AMACE paper.
 * Same-priority alternatives are processed together; iteration order never breaks ties.
 */
public final class CandidateSelector {
    public enum Reason {
        NOT_REACHABLE, ACCEPTED_TRUSTED, ACCEPTED_DIRECT_CALL, ACCEPTED_INFERRED,
        BLOCKED, HIGHER_PRIORITY_OVERLAP, AMBIGUOUS_OVERLAP, UNREACHABLE_AFTER_CONFLICT
    }

    public record Decision(boolean accepted, int tier, Reason reason, String detail) {}
    public record UnresolvedEdge(Site from, Site target, String reason) {}

    public record Selection(Map<Site, Decision> decisions, Set<Site> accepted,
            Map<Site, Integer> entryTiers, Map<Site, Set<Site>> functionBodies,
            Map<Site, String> deferredFunctions, List<UnresolvedEdge> unresolvedEdges) {
        public Selection {
            decisions = immutableMap(decisions);
            accepted = immutableSet(accepted);
            entryTiers = immutableMap(entryTiers);
            var bodies = new TreeMap<Site, Set<Site>>();
            functionBodies.forEach((site, body) -> bodies.put(site, immutableSet(body)));
            functionBodies = immutableMap(bodies);
            deferredFunctions = immutableMap(deferredFunctions);
            unresolvedEdges = List.copyOf(unresolvedEdges);
        }
    }

    public Selection select(Map<Site, Candidate> candidates, Set<Site> trustedRoots,
            Set<Site> inferredEntries, Set<Site> noReturnCalls, Set<Site> blockedCandidates,
            Runnable checkCancelled) {
        Objects.requireNonNull(candidates); Objects.requireNonNull(trustedRoots);
        Objects.requireNonNull(inferredEntries); Objects.requireNonNull(noReturnCalls);
        Objects.requireNonNull(blockedCandidates); Objects.requireNonNull(checkCancelled);
        candidates.forEach((site, candidate) -> {
            if (!site.equals(candidate.site())) throw new IllegalArgumentException("Candidate map key mismatch");
        });
        var state = new State(candidates, noReturnCalls, blockedCandidates, checkCancelled);
        state.runPass(trustedRoots, 1, false);
        // Only accepted callers provide independent roots for the second pass.
        var callRoots = new TreeSet<Site>();
        for (Site accepted : state.accepted.keySet()) {
            checkCancelled.run();
            callRoots.addAll(functionCallTargets(candidates.get(accepted)));
        }
        state.runPass(callRoots, 2, true);
        state.runPass(inferredEntries, 3, true);
        return state.finish(trustedRoots);
    }

    private static final class State {
        private final Map<Site, Candidate> candidates;
        private final Set<Site> noReturnCalls;
        private final Set<Site> blocked;
        private final Runnable checkCancelled;
        private final NavigableMap<Site, Candidate> accepted = new TreeMap<>();
        // Stronger ambiguous interpretations reserve their disputed bytes. We must
        // not fill that hole later by pretending the same instruction is weaker evidence.
        private final NavigableMap<Site, Candidate> disputed = new TreeMap<>();
        private final Map<Site, Decision> decisions = new TreeMap<>();
        private final Map<Site, Integer> entryTiers = new TreeMap<>();

        private State(Map<Site, Candidate> candidates, Set<Site> noReturnCalls,
                Set<Site> blocked, Runnable checkCancelled) {
            this.candidates = candidates; this.noReturnCalls = noReturnCalls;
            this.blocked = blocked; this.checkCancelled = checkCancelled;
            for (Site site : candidates.keySet()) {
                decisions.put(site, blocked.contains(site)
                    ? new Decision(false, 0, Reason.BLOCKED, "Existing definition or instruction outside application scope")
                    : new Decision(false, 0, Reason.NOT_REACHABLE, "No selected root reaches this candidate"));
            }
        }

        private void runPass(Collection<Site> roots, int tier, boolean followCalls) {
            var eligible = new TreeMap<Site, Candidate>();
            var visited = new HashSet<Site>();
            var pending = new ArrayDeque<Site>(new TreeSet<>(roots));
            while (!pending.isEmpty()) {
                checkCancelled.run();
                Site site = pending.removeFirst();
                if (!visited.add(site)) continue;
                Candidate candidate = candidates.get(site);
                if (candidate == null || blocked.contains(site)) continue;
                if (accepted.containsKey(site)) continue;
                Candidate stronger = firstOverlap(accepted, candidate);
                if (stronger == null) stronger = firstOverlap(disputed, candidate);
                if (stronger != null) {
                    Decision old = decisions.get(site);
                    if (old.reason() != Reason.AMBIGUOUS_OVERLAP) {
                        decisions.put(site, new Decision(false, tier, Reason.HIGHER_PRIORITY_OVERLAP,
                            "Overlaps stronger accepted or disputed interpretation at " + stronger.site()));
                    }
                    continue;
                }
                eligible.put(site, candidate);
                pending.addAll(successors(candidate, followCalls));
            }

            Set<Site> ambiguous = allOverlapParticipants(eligible, checkCancelled);
            for (Site site : ambiguous) {
                checkCancelled.run();
                disputed.put(site, eligible.get(site));
                decisions.put(site, new Decision(false, tier, Reason.AMBIGUOUS_OVERLAP,
                    "Overlapping reachable candidates have equal evidence priority"));
            }

            // Recompute reachability after removing ambiguity. In particular, a call
            // reached only through a rejected instruction cannot independently seed a callee.
            var reachable = new TreeSet<Site>();
            pending.addAll(new TreeSet<>(roots));
            var traversed = new HashSet<Site>();
            while (!pending.isEmpty()) {
                checkCancelled.run();
                Site site = pending.removeFirst();
                if (!traversed.add(site)) continue;
                if (accepted.containsKey(site)) { reachable.add(site); continue; }
                if (!eligible.containsKey(site) || ambiguous.contains(site)) continue;
                reachable.add(site);
                pending.addAll(successors(eligible.get(site), followCalls));
            }

            for (var item : eligible.entrySet()) {
                checkCancelled.run();
                Site site = item.getKey();
                if (ambiguous.contains(site)) continue;
                if (reachable.contains(site)) {
                    accepted.put(site, item.getValue());
                    decisions.put(site, new Decision(true, tier, acceptedReason(tier),
                        "Reachable from surviving priority-" + tier + " evidence"));
                } else {
                    decisions.put(site, new Decision(false, tier, Reason.UNREACHABLE_AFTER_CONFLICT,
                        "Every path from this pass's roots crosses a rejected interpretation"));
                }
            }
            for (Site root : roots) {
                checkCancelled.run();
                if (reachable.contains(root) && accepted.containsKey(root)) {
                    entryTiers.merge(root, tier, Math::min);
                }
            }
            if (followCalls) {
                for (Site site : reachable) {
                    checkCancelled.run();
                    Candidate caller = candidates.get(site);
                    // Fixed higher-priority nodes have already contributed their call
                    // roots; they must not promote their new descendants to this pass.
                    Decision decision = decisions.get(site);
                    if (decision == null || decision.tier() != tier) continue;
                    for (Site target : functionCallTargets(caller)) {
                        if (reachable.contains(target) && accepted.containsKey(target)) {
                            entryTiers.merge(target, tier, Math::min);
                        }
                    }
                }
            }
        }

        private List<Site> successors(Candidate candidate, boolean followCalls) {
            var result = new LinkedHashSet<Site>();
            if (!noReturnCalls.contains(candidate.site())) result.addAll(candidate.localSuccessors());
            if (followCalls) result.addAll(functionCallTargets(candidate));
            return List.copyOf(result);
        }

        private Selection finish(Set<Site> trustedRoots) {
            var tentativeBodies = new TreeMap<Site, Set<Site>>();
            for (var item : entryTiers.entrySet()) {
                checkCancelled.run();
                Site entry = item.getKey();
                int tier = item.getValue();
                var body = new TreeSet<Site>();
                var pending = new ArrayDeque<Site>();
                pending.add(entry);
                while (!pending.isEmpty()) {
                    checkCancelled.run();
                    Site site = pending.removeFirst();
                    if (!accepted.containsKey(site) || body.contains(site)) continue;
                    Integer otherTier = entryTiers.get(site);
                    // A speculative entry cannot truncate a more strongly supported
                    // function. Its overlapping tentative body will instead be deferred.
                    if (!site.equals(entry) && otherTier != null && otherTier <= tier) continue;
                    body.add(site);
                    Candidate candidate = accepted.get(site);
                    if (!noReturnCalls.contains(site)) pending.addAll(candidate.localSuccessors());
                }
                if (!body.isEmpty()) tentativeBodies.put(entry, body);
            }
            var deferred = new TreeMap<Site, String>();
            var owners = new HashMap<Site, List<Site>>();
            tentativeBodies.forEach((entry, body) -> {
                for (Site site : body) {
                    checkCancelled.run();
                    owners.computeIfAbsent(site, ignored -> new ArrayList<>()).add(entry);
                }
            });
            for (var item : owners.entrySet()) {
                checkCancelled.run();
                List<Site> entries = item.getValue();
                if (entries.size() < 2) continue;
                int strongest = entries.stream().mapToInt(entryTiers::get).min().orElseThrow();
                long strongestCount = entries.stream().filter(e -> entryTiers.get(e) == strongest).count();
                for (Site entry : entries) {
                    if (entryTiers.get(entry) > strongest || strongestCount > 1) {
                        deferred.putIfAbsent(entry, "Function body shares instruction " + item.getKey()
                            + " with an equal or stronger function hypothesis");
                    }
                }
            }
            var bodies = new TreeMap<Site, Set<Site>>(tentativeBodies);
            deferred.keySet().forEach(bodies::remove);
            var unresolved = new ArrayList<UnresolvedEdge>();
            for (Candidate candidate : accepted.values()) {
                checkCancelled.run();
                if (candidate.flow() == FlowKind.INDIRECT_JUMP || candidate.flow() == FlowKind.INDIRECT_CALL) {
                    unresolved.add(new UnresolvedEdge(candidate.site(), null, "Indirect control-flow target is unresolved"));
                }
                var outgoing = new LinkedHashSet<Site>(successors(candidate, true));
                for (Site target : outgoing) {
                    if (accepted.containsKey(target)) continue;
                    Decision rejected = decisions.get(target);
                    unresolved.add(new UnresolvedEdge(candidate.site(), target,
                        rejected == null ? "Target has no decoded candidate in scope"
                            : "Target was not adopted: " + rejected.reason()));
                }
            }
            for (Site root : new TreeSet<>(trustedRoots)) {
                if (!candidates.containsKey(root)) {
                    unresolved.add(new UnresolvedEdge(null, root, "Trusted entry has no decoded candidate in scope"));
                }
            }
            return new Selection(decisions, accepted.keySet(), entryTiers, bodies, deferred, unresolved);
        }
    }

    private static List<Site> functionCallTargets(Candidate candidate) {
        if (candidate == null || candidate.flow() != FlowKind.CALL) return List.of();
        // x86 call-next is position discovery, not independent evidence of a function.
        return candidate.targets().stream().filter(t -> !t.equals(candidate.fallthrough())).distinct().toList();
    }

    private static Reason acceptedReason(int tier) {
        return switch (tier) {
            case 1 -> Reason.ACCEPTED_TRUSTED;
            case 2 -> Reason.ACCEPTED_DIRECT_CALL;
            case 3 -> Reason.ACCEPTED_INFERRED;
            default -> throw new IllegalArgumentException("Unknown evidence tier");
        };
    }

    /** At most 15 previous byte positions can overlap an x86 instruction. */
    private static Candidate firstOverlap(NavigableMap<Site, Candidate> indexed, Candidate candidate) {
        var entry = indexed.floorEntry(candidate.site());
        while (entry != null && entry.getKey().space().equals(candidate.site().space())
                && Long.compareUnsigned(candidate.site().offset() - entry.getKey().offset(), 15) < 0) {
            if (candidate.overlaps(entry.getValue())) return entry.getValue();
            entry = indexed.lowerEntry(entry.getKey());
        }
        entry = indexed.higherEntry(candidate.site());
        while (entry != null && entry.getKey().space().equals(candidate.site().space())
                && Long.compareUnsigned(entry.getKey().offset() - candidate.site().offset(), candidate.length()) < 0) {
            if (candidate.overlaps(entry.getValue())) return entry.getValue();
            entry = indexed.higherEntry(entry.getKey());
        }
        return null;
    }

    private static Set<Site> allOverlapParticipants(NavigableMap<Site, Candidate> indexed, Runnable cancel) {
        var ambiguous = new TreeSet<Site>();
        var active = new ArrayList<Candidate>();
        for (Candidate candidate : indexed.values()) {
            cancel.run();
            active.removeIf(old -> !old.site().space().equals(candidate.site().space())
                || Long.compareUnsigned(candidate.site().offset() - old.site().offset(), old.length()) >= 0);
            for (Candidate old : active) {
                if (old.overlaps(candidate)) {
                    ambiguous.add(old.site()); ambiguous.add(candidate.site());
                }
            }
            active.add(candidate);
        }
        return ambiguous;
    }

    private static <V> Map<Site, V> immutableMap(Map<Site, V> source) {
        return Collections.unmodifiableMap(new LinkedHashMap<>(new TreeMap<>(source)));
    }

    private static Set<Site> immutableSet(Collection<Site> source) {
        return Collections.unmodifiableSet(new LinkedHashSet<>(new TreeSet<>(source)));
    }
}
