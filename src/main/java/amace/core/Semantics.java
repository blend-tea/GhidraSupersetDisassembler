package amace.core;

import java.util.List;
import java.util.Objects;

/** Immutable, dependency-free P-code micro-CFG. Machine CALL/RET effects are normalized. */
public record Semantics(List<Op> operations, boolean supported, Value indirectTarget,
        Long callStackAdjustment) {
    public Semantics { operations = List.copyOf(operations); }
    public static Semantics identity() { return new Semantics(List.of(), true, null, 0L); }
    public static Semantics unknown() { return new Semantics(List.of(), false, null, null); }

    public enum Kind { REGISTER, UNIQUE, CONSTANT, MEMORY }

    /** Register offsets and sizes are bytes relative to the canonical base register. */
    public record Value(Kind kind, String name, int byteOffset, int size, int baseSize, long constant) {
        public Value {
            Objects.requireNonNull(kind);
            name = name == null ? "" : name.toLowerCase(java.util.Locale.ROOT);
            if (size < 1 || baseSize < size || byteOffset < 0) throw new IllegalArgumentException("value width");
        }
        public static Value register(String name, int size) { return new Value(Kind.REGISTER,name,0,size,size,0); }
        public static Value temporary(long offset, int size) { return new Value(Kind.UNIQUE,"u"+Long.toUnsignedString(offset,16),0,size,size,offset); }
        public static Value constant(long value, int size) { return new Value(Kind.CONSTANT,"",0,size,size,value); }
        public boolean fullRegister() { return kind == Kind.REGISTER && byteOffset == 0 && size == baseSize; }
        public String key() { return kind+":"+name+":"+byteOffset+":"+size; }
    }

    /** branchTarget is a local operation index, or -1 when there is no local branch. */
    public record Op(String opcode, Value output, List<Value> inputs, int branchTarget) {
        public Op {
            opcode = Objects.requireNonNull(opcode).toUpperCase(java.util.Locale.ROOT);
            inputs = List.copyOf(inputs);
        }
        public Op(String opcode, Value output, List<Value> inputs) { this(opcode,output,inputs,-1); }
    }
}
