package amace.core;

/** Address with address-space identity and unsigned ordering. */
public record Site(String space, long offset) implements Comparable<Site> {
    public Site { if (space == null || space.isBlank()) throw new IllegalArgumentException("address space"); }
    public Site add(int amount) {
        long next = offset + amount;
        if ((amount > 0 && Long.compareUnsigned(next, offset) < 0)
                || (amount < 0 && Long.compareUnsigned(next, offset) > 0)) {
            throw new ArithmeticException("address wraps");
        }
        return new Site(space, next);
    }
    @Override public int compareTo(Site other) {
        int c = space.compareTo(other.space);
        return c != 0 ? c : Long.compareUnsigned(offset, other.offset);
    }
    @Override public String toString() { return space + ":" + Long.toUnsignedString(offset, 16); }
}
