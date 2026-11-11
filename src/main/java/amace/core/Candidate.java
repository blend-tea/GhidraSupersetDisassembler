package amace.core;

import java.util.List;
import java.util.Objects;

/** A decoded instruction. Overlap is deliberately allowed in candidate collections. */
public record Candidate(Site site, byte[] bytes, String mnemonic, String operands,
        FlowKind flow, List<Site> targets, Site fallthrough, Semantics semantics) {
    public Candidate {
        Objects.requireNonNull(site); Objects.requireNonNull(flow); Objects.requireNonNull(semantics);
        bytes = bytes.clone(); targets = List.copyOf(targets);
        if (bytes.length < 1 || bytes.length > 15) throw new IllegalArgumentException("x86 instruction length");
    }
    @Override public byte[] bytes() { return bytes.clone(); }
    public int length() { return bytes.length; }
    public boolean overlaps(Candidate other) {
        if (!site.space().equals(other.site.space())) return false;
        long a = site.offset(), b = other.site.offset();
        return Long.compareUnsigned(a, b) <= 0 ? Long.compareUnsigned(b - a, length()) < 0
                : Long.compareUnsigned(a - b, other.length()) < 0;
    }
    public List<Site> localSuccessors() {
        var result = new java.util.ArrayList<Site>();
        if (flow != FlowKind.CALL && flow != FlowKind.INDIRECT_CALL) result.addAll(targets);
        if (fallthrough != null && flow != FlowKind.RETURN && flow != FlowKind.HALT
                && flow != FlowKind.JUMP && flow != FlowKind.INDIRECT_JUMP) result.add(fallthrough);
        return List.copyOf(result);
    }
}
