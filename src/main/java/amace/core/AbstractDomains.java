package amace.core;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Bounded domains from AMACE sections 3 and 4. The limit bounds the number of
 * observations, not the numeric stack depth. Every merge is independent of input
 * iteration order; counts saturate rather than wrapping around.
 */
public final class AbstractDomains {
    private AbstractDomains() { }

    /** Sentinel for an unknown maximum depth. */
    public static final long MAX_UNKNOWN = Long.MIN_VALUE;
    public enum DepthKind { CONCRETE, UNKNOWN, AGGREGATE }

    public record Depth(DepthKind kind, long value, long maxDepth, long count) {
        public Depth {
            Objects.requireNonNull(kind);
            if (count < 1) throw new IllegalArgumentException("observation count must be positive");
            if (kind != DepthKind.CONCRETE) value = 0;
            if (kind == DepthKind.UNKNOWN) maxDepth = MAX_UNKNOWN;
        }
        public static Depth zero() { return new Depth(DepthKind.CONCRETE, 0, 0, 1); }
        public static Depth unknown() { return unknown(1); }
        public static Depth unknown(long count) { return new Depth(DepthKind.UNKNOWN, 0, MAX_UNKNOWN, count); }
        public static Depth concrete(long value, long maxDepth, long count) {
            return new Depth(DepthKind.CONCRETE, value, maxDepth, count);
        }
    }

    private record DepthKey(DepthKind kind, long value) { }
    private static final Comparator<Depth> DEPTH_ORDER = Comparator
        .comparing(Depth::kind).thenComparingLong(Depth::value);
    private static final Comparator<Depth> DEPTH_COUNT_ORDER = Comparator
        .comparingLong(Depth::count).thenComparing(DEPTH_ORDER);

    /** Union by depth, then aggregate the least frequent non-unknown depths. */
    public static List<Depth> mergeDepths(Collection<Depth> input, int limit) {
        requireLimit(limit);
        Map<DepthKey, Depth> map = new LinkedHashMap<>();
        for (Depth d : input) {
            Objects.requireNonNull(d);
            var key = new DepthKey(d.kind(), d.value());
            map.merge(key, d, (a, b) -> new Depth(a.kind(), a.value(),
                maximum(a.maxDepth(), b.maxDepth()), saturatingAdd(a.count(), b.count())));
        }
        var result = new ArrayList<>(map.values());
        if (result.size() > limit) {
            Depth aggregate = result.stream().filter(d -> d.kind() == DepthKind.AGGREGATE).findFirst().orElse(null);
            var eligible = new ArrayList<>(result.stream()
                .filter(d -> d.kind() == DepthKind.CONCRETE).toList());
            eligible.sort(DEPTH_COUNT_ORDER);
            int needed = result.size() - limit + (aggregate == null ? 1 : 0);
            // With limit=1 an unknown and another observation cannot both be kept.
            // Discarding information to unknown is sounder than inventing mismatch evidence.
            if (needed > eligible.size()) {
                long count = sumCounts(result.stream().map(Depth::count).toList());
                result.clear();
                result.add(Depth.unknown(count));
            } else {
                long count = aggregate == null ? 0 : aggregate.count();
                long max = aggregate == null ? Long.MIN_VALUE + 1 : aggregate.maxDepth();
                for (int i = 0; i < needed; i++) {
                    Depth d = eligible.get(i);
                    result.remove(d);
                    count = saturatingAdd(count, d.count());
                    max = i == 0 && aggregate == null ? d.maxDepth() : maximum(max, d.maxDepth());
                }
                if (aggregate != null) result.remove(aggregate);
                result.add(new Depth(DepthKind.AGGREGATE, 0, max, count));
            }
        }
        result.sort(DEPTH_ORDER);
        return List.copyOf(result);
    }

    /** Backwards transfer for SP=SP+delta; maximum records the full observed path. */
    public static List<Depth> shiftDepths(List<Depth> depths, long delta) {
        var result = new ArrayList<Depth>();
        for (Depth d : depths) {
            if (d.kind() == DepthKind.UNKNOWN) result.add(d);
            else if (d.kind() == DepthKind.AGGREGATE) result.add(d);
            else {
                try {
                    long value = Math.addExact(d.value(), delta);
                    result.add(new Depth(DepthKind.CONCRETE, value,
                        d.maxDepth() == MAX_UNKNOWN ? MAX_UNKNOWN : Math.max(d.maxDepth(), value), d.count()));
                } catch (ArithmeticException overflow) {
                    result.add(Depth.unknown(d.count()));
                }
            }
        }
        // Overflow may turn multiple concrete depths into the same unknown depth.
        return mergeDepths(result, Math.max(1, depths.size()));
    }

    public enum SourceKind { REGISTER, STACK, UNKNOWN, AGGREGATE }

    public record StackSlot(String base, long offset, boolean aggregate) {
        public StackSlot {
            base = Objects.requireNonNull(base).toLowerCase(Locale.ROOT);
            if (base.isBlank()) throw new IllegalArgumentException("stack base");
            if (aggregate) offset = 0;
        }
    }

    /**
     * The source supplies destination at return; slot optionally remembers the
     * intermediate saved location after a store is traversed backwards.
     */
    public record Restore(SourceKind kind, String register, StackSlot slot,
            String destination, long count) {
        public Restore {
            Objects.requireNonNull(kind);
            register = register == null ? "" : register.toLowerCase(Locale.ROOT);
            destination = Objects.requireNonNull(destination).toLowerCase(Locale.ROOT);
            if (destination.isBlank() || count < 1) throw new IllegalArgumentException("restore observation");
            if (kind == SourceKind.REGISTER && register.isBlank()) throw new IllegalArgumentException("source register");
            if (kind == SourceKind.STACK && slot == null) throw new IllegalArgumentException("source stack slot");
            if (kind == SourceKind.UNKNOWN || kind == SourceKind.AGGREGATE) { register = ""; slot = null; }
        }
        public static Restore identity(String register) {
            return new Restore(SourceKind.REGISTER, register, null, register, 1);
        }
        public static Restore unknown(String destination, long count) {
            return new Restore(SourceKind.UNKNOWN, "", null, destination, count);
        }
        public boolean mismatch() {
            return switch (kind) {
                case REGISTER -> !register.equals(destination);
                case STACK, AGGREGATE -> true;
                case UNKNOWN -> false;
            };
        }
    }

    private record RestoreKey(SourceKind kind, String register, StackSlot slot, String destination) {
        RestoreKey(Restore r) { this(r.kind(), r.register(), r.slot(), r.destination()); }
    }
    private static final Comparator<StackSlot> SLOT_ORDER = Comparator.nullsFirst(Comparator
        .comparing(StackSlot::base).thenComparing(StackSlot::aggregate).thenComparingLong(StackSlot::offset));
    private static final Comparator<Restore> RESTORE_ORDER = Comparator
        .comparing(Restore::destination).thenComparing(Restore::kind)
        .thenComparing(Restore::register).thenComparing(Restore::slot, SLOT_ORDER);
    private static final Comparator<Restore> RESTORE_COUNT_ORDER = Comparator
        .comparingLong(Restore::count).thenComparing(RESTORE_ORDER);

    /** Bounded union, separately for each restored destination register. */
    public static List<Restore> mergeRestores(Collection<Restore> input, int limit) {
        requireLimit(limit);
        Map<RestoreKey, Restore> map = new LinkedHashMap<>();
        for (Restore r : input) {
            Objects.requireNonNull(r);
            map.merge(new RestoreKey(r), r, AbstractDomains::combineSameRestore);
        }
        Map<String, List<Restore>> byDestination = new TreeMap<>();
        for (Restore r : map.values()) byDestination.computeIfAbsent(r.destination(), ignored -> new ArrayList<>()).add(r);
        var result = new ArrayList<Restore>();
        for (var entry : byDestination.entrySet()) {
            var observations = entry.getValue();
            observations.sort(RESTORE_ORDER);
            while (observations.size() > limit && mergeOneSlotPair(observations)) {
                // Table 5 / section 4.2 first merges equal sources with different stack offsets.
            }
            if (observations.size() > limit) aggregateRestoreCounts(observations, limit, entry.getKey());
            result.addAll(observations);
        }
        result.sort(RESTORE_ORDER);
        return List.copyOf(result);
    }

    private static Restore combineSameRestore(Restore a, Restore b) {
        return new Restore(a.kind(), a.register(), a.slot(), a.destination(), saturatingAdd(a.count(), b.count()));
    }

    private static boolean mergeOneSlotPair(List<Restore> list) {
        list.sort(RESTORE_ORDER);
        for (int i = 0; i < list.size(); i++) {
            Restore a = list.get(i);
            if (a.slot() == null) continue;
            for (int j = i + 1; j < list.size(); j++) {
                Restore b = list.get(j);
                if (b.slot() == null || a.kind() != b.kind() || !a.register().equals(b.register())
                        || !a.slot().base().equals(b.slot().base())) continue;
                Restore merged = new Restore(a.kind(), a.register(),
                    new StackSlot(a.slot().base(), 0, true), a.destination(), saturatingAdd(a.count(), b.count()));
                list.remove(j); list.remove(i);
                // A previous aggregate slot can coincide with this result.
                for (int n = 0; n < list.size(); n++) {
                    if (new RestoreKey(list.get(n)).equals(new RestoreKey(merged))) {
                        merged = combineSameRestore(merged, list.remove(n));
                        break;
                    }
                }
                list.add(merged);
                return true;
            }
        }
        return false;
    }

    private static void aggregateRestoreCounts(List<Restore> list, int limit, String destination) {
        Restore aggregate = list.stream().filter(r -> r.kind() == SourceKind.AGGREGATE).findFirst().orElse(null);
        var eligible = new ArrayList<>(list.stream()
            .filter(r -> r.kind() != SourceKind.UNKNOWN && r.kind() != SourceKind.AGGREGATE).toList());
        eligible.sort(RESTORE_COUNT_ORDER);
        int needed = list.size() - limit + (aggregate == null ? 1 : 0);
        if (needed > eligible.size()) {
            long count = sumCounts(list.stream().map(Restore::count).toList());
            list.clear(); list.add(Restore.unknown(destination, count));
            return;
        }
        long count = aggregate == null ? 0 : aggregate.count();
        if (aggregate != null) list.remove(aggregate);
        for (int i = 0; i < needed; i++) {
            Restore r = eligible.get(i);
            list.remove(r);
            count = saturatingAdd(count, r.count());
        }
        list.add(new Restore(SourceKind.AGGREGATE, "", null, destination, count));
    }

    /** Unknown observations do not constitute mismatch; a strict majority is required. */
    public static boolean registersCompatible(Collection<Restore> restorations) {
        // Compare mathematical sums of the stored counts. Saturating the total
        // before this comparison could turn a tie into a false majority.
        Map<String, BigInteger[]> counts = new TreeMap<>();
        for (Restore r : restorations) {
            BigInteger[] pair = counts.computeIfAbsent(r.destination(), ignored ->
                new BigInteger[] { BigInteger.ZERO, BigInteger.ZERO });
            BigInteger count = BigInteger.valueOf(r.count());
            pair[0] = pair[0].add(count);
            if (r.mismatch()) pair[1] = pair[1].add(count);
        }
        for (BigInteger[] pair : counts.values()) if (pair[1].shiftLeft(1).compareTo(pair[0]) > 0) return false;
        return true;
    }

    public static long saturatingAdd(long a, long b) {
        if (a < 0 || b < 0) throw new IllegalArgumentException("negative count");
        return a > Long.MAX_VALUE - b ? Long.MAX_VALUE : a + b;
    }

    private static long maximum(long a, long b) {
        return a == MAX_UNKNOWN || b == MAX_UNKNOWN ? MAX_UNKNOWN : Math.max(a, b);
    }
    private static long sumCounts(Collection<Long> values) {
        long sum = 0;
        for (long value : values) sum = saturatingAdd(sum, value);
        return sum;
    }
    private static void requireLimit(int limit) {
        if (limit < 1) throw new IllegalArgumentException("domain limit must be positive");
    }
}
