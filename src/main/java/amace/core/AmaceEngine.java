package amace.core;

import java.util.*;
import amace.core.AbstractDomains.*;
import amace.core.Semantics.*;

/**
 * Bounded backward analyses from AMACE sections 2--5. The complete decoded
 * graph is the input: no Listing or non-overlap decision enters these equations.
 * Unknown loop successors and unsupported effects lose evidence rather than
 * manufacture a positive function or non-returning-call classification.
 */
public final class AmaceEngine {
    public static final int LIMIT = 10;

    public record Facts(Set<String> requiredRegisters, boolean pointerUnknown,
            List<Depth> depths, Map<String,List<Restore>> restorations,
            boolean pointerCompatible, boolean stackCompatible, boolean registersCompatible,
            boolean concreteEvidence, boolean entryCandidate, String note) {
        public Facts {
            requiredRegisters=Set.copyOf(requiredRegisters); depths=List.copyOf(depths);
            var copy=new TreeMap<String,List<Restore>>();
            restorations.forEach((k,v)->copy.put(k,List.copyOf(v)));
            restorations=Collections.unmodifiableMap(copy);
        }
        public String pointerSummary() {
            return (pointerCompatible?"compatible":"incompatible")+" "+requiredRegisters
                    +(pointerUnknown?" (unknown path/effect)":"");
        }
        public String stackSummary() { return (stackCompatible?"compatible ":"incompatible ")+depths; }
        public String registerSummary() {
            long saved=restorations.values().stream().flatMap(Collection::stream)
                .filter(r->r.kind()==SourceKind.REGISTER && r.register().equals(r.destination()) && r.slot()!=null).count();
            return (registersCompatible?"compatible":"mismatch majority")+"; active restores="+saved;
        }
    }
    public record Analysis(Map<Site,Facts> facts, Set<Site> inferredEntries, Set<Site> noReturnCalls) {
        public Analysis {
            facts=Collections.unmodifiableMap(new TreeMap<>(facts));
            inferredEntries=Collections.unmodifiableSet(new TreeSet<>(inferredEntries));
            noReturnCalls=Collections.unmodifiableSet(new TreeSet<>(noReturnCalls));
        }
    }

    public Analysis analyze(Collection<Candidate> input, Abi abi, Set<Site> knownNoReturnTargets,
            Runnable checkCancelled) {
        var possible=new HashSet<Site>();
        var strong=new HashSet<Site>();
        for(Candidate c:input) {
            if((c.site().offset()&15)==0) possible.add(c.site());
            if(c.flow()==FlowKind.CALL) possible.addAll(c.targets());
            if(isPrologue(c,abi)) { possible.add(c.site()); strong.add(c.site()); }
        }
        return analyze(input,abi,knownNoReturnTargets,possible,strong,checkCancelled);
    }
    public Analysis analyze(Collection<Candidate> input, Abi abi, Set<Site> knownNoReturnTargets,
            Set<Site> possibleEntries, Runnable checkCancelled) {
        return analyze(input,abi,knownNoReturnTargets,possibleEntries,Set.of(),checkCancelled);
    }
    public Analysis analyze(Collection<Candidate> input, Abi abi, Set<Site> knownNoReturnTargets,
            Set<Site> possibleEntries, Set<Site> strongEntryEvidence, Runnable checkCancelled) {
        Objects.requireNonNull(abi); Objects.requireNonNull(checkCancelled);
        var graph=new TreeMap<Site,Candidate>();
        for(Candidate c:input) { checkCancelled.run(); if(graph.put(c.site(),c)!=null) throw new IllegalArgumentException("duplicate candidate "+c.site()); }
        var noReturnCalls=new HashSet<Site>();
        for(Candidate c:graph.values()) if(isCall(c) && !c.targets().isEmpty()
                && c.targets().stream().allMatch(knownNoReturnTargets::contains)) noReturnCalls.add(c.site());
        Map<Site,Facts> initial=analyzeCore(graph,abi,noReturnCalls,checkCancelled);
        // Phase 2 needs independent entry evidence, rather than treating every
        // stack-balanced instruction after an ordinary call as a new function.
        for(Candidate c:graph.values()) {
            checkCancelled.run();
            Facts next=c.fallthrough()==null?null:initial.get(c.fallthrough());
            if(isCall(c) && c.fallthrough()!=null && strongEntryEvidence.contains(c.fallthrough())
                    && possibleEntries.contains(c.fallthrough()) && next!=null && next.entryCandidate()
                    && !next.pointerUnknown() && c.semantics().supported()) noReturnCalls.add(c.site());
        }
        // Phase 3 propagates all-exits-noreturn evidence once through reverse
        // dependency edges. Unknown targets and non-terminating SCCs are not proof.
        propagateNoReturn(graph,noReturnCalls,checkCancelled);
        Map<Site,Facts> facts=noReturnCalls.isEmpty()?initial:analyzeCore(graph,abi,noReturnCalls,checkCancelled);
        var entries=new HashSet<Site>();
        for(Site s:possibleEntries) {
            Facts f=facts.get(s); Candidate c=graph.get(s);
            if(f!=null && c!=null && f.entryCandidate() && !isBareBoundary(c)) entries.add(s);
        }
        return new Analysis(facts,entries,noReturnCalls);
    }

    /** Structural candidate generation is separate from the semantic classifier. */
    public static boolean isPrologue(Candidate c, Abi abi) {
        byte[] b=c.bytes();
        return b.length==1 && (b[0]&255)==0x55 // push bp; metadata may supply other starts
            || b.length>=3 && (b[0]&255)==0x48 && (b[1]&255)==0x83 && (b[2]&255)==0xec
            || abi.bits()==32 && b.length>=2 && (b[0]&255)==0x83 && (b[1]&255)==0xec;
    }
    private static boolean isBareBoundary(Candidate c) {
        String m=c.mnemonic().toLowerCase(Locale.ROOT);
        return c.flow()==FlowKind.RETURN || c.flow()==FlowKind.HALT || m.equals("nop")
            || Set.of("pop","popa","popad","popf","popfd","popfq").contains(m);
    }
    private static boolean isCall(Candidate c) { return c.flow()==FlowKind.CALL || c.flow()==FlowKind.INDIRECT_CALL; }

    private Map<Site,Facts> analyzeCore(Map<Site,Candidate> graph, Abi abi, Set<Site> noReturnCalls,
            Runnable cancel) {
        Map<Site,List<Site>> edges=new HashMap<>();
        for(Candidate c:graph.values()) edges.put(c.site(),successors(c,noReturnCalls));
        List<List<Site>> components=components(graph.keySet(),edges,cancel);
        Map<Site,State> states=new HashMap<>();
        Map<Site,Facts> result=new TreeMap<>();
        for(List<Site> component:components) for(Site site:backwardOrder(component,edges,cancel)) {
            cancel.run(); Candidate c=graph.get(site); State out;
            if(c.flow()==FlowKind.RETURN) out=State.returnState(abi);
            else if(c.flow()==FlowKind.HALT || c.flow()==FlowKind.INDIRECT_JUMP || noReturnCalls.contains(site)) out=new State();
            else {
                var successors=edges.get(site);
                var joined=new ArrayList<State>();
                for(Site s:successors) joined.add(states.getOrDefault(s,State.unknownBoundary()));
                out=joined.isEmpty()?State.unknownBoundary():join(joined);
            }
            State before=transferInstruction(c,out,abi);
            before=normalizeBoundary(before,abi);
            states.put(site,before);
            result.put(site,toFacts(c,before,abi));
        }
        return result;
    }

    private static List<Site> successors(Candidate c, Set<Site> noReturnCalls) {
        if(noReturnCalls.contains(c.site())) return List.of();
        return c.localSuccessors().stream().distinct().sorted().toList();
    }

    private static void propagateNoReturn(Map<Site,Candidate> graph, Set<Site> noReturnCalls, Runnable cancel) {
        var predecessors=new HashMap<Site,List<Site>>();
        var callers=new HashMap<Site,List<Site>>();
        var pending=new HashMap<Site,Integer>();
        var proven=new HashSet<Site>();
        var queue=new ArrayDeque<Site>();
        for(Candidate c:graph.values()) {
            cancel.run();
            List<Site> succ=c.localSuccessors().stream().distinct().toList();
            pending.put(c.site(),succ.size());
            for(Site s:succ) predecessors.computeIfAbsent(s,k->new ArrayList<>()).add(c.site());
            if(isCall(c)) for(Site s:c.targets()) callers.computeIfAbsent(s,k->new ArrayList<>()).add(c.site());
            if(c.semantics().supported() && (c.flow()==FlowKind.HALT || noReturnCalls.contains(c.site()))) {
                proven.add(c.site()); queue.add(c.site());
            }
        }
        while(!queue.isEmpty()) {
            cancel.run(); Site site=queue.remove();
            for(Site p:predecessors.getOrDefault(site,List.of())) {
                int n=pending.computeIfPresent(p,(k,v)->v-1);
                Candidate c=graph.get(p);
                if(n==0 && c.semantics().supported() && c.flow()!=FlowKind.RETURN && c.flow()!=FlowKind.INDIRECT_JUMP
                        && !c.localSuccessors().isEmpty() && proven.add(p)) queue.add(p);
            }
            for(Site call:callers.getOrDefault(site,List.of())) {
                Candidate c=graph.get(call);
                if(c.semantics().supported() && !c.targets().isEmpty() && c.targets().stream().allMatch(proven::contains)) {
                    noReturnCalls.add(call);
                    if(proven.add(call)) queue.add(call);
                }
            }
        }
    }

    private static final class Requirements {
        final Map<String,BitSet> bytes=new HashMap<>();
        Requirements copy() { var r=new Requirements(); bytes.forEach((k,v)->r.bytes.put(k,(BitSet)v.clone())); return r; }
        void add(Value v) {
            if(v==null || v.kind()==Kind.CONSTANT) return;
            String key=key(v); BitSet bits=bytes.computeIfAbsent(key,k->new BitSet());
            bits.set(v.byteOffset(),v.byteOffset()+v.size());
        }
        boolean discharge(Value v) {
            if(v==null || v.kind()==Kind.CONSTANT) return false;
            BitSet bits=bytes.get(key(v)); if(bits==null) return false;
            BitSet range=bits.get(v.byteOffset(),v.byteOffset()+v.size());
            bits.clear(v.byteOffset(),v.byteOffset()+v.size());
            if(bits.isEmpty()) bytes.remove(key(v));
            return !range.isEmpty();
        }
        void removeRegister(String register) { bytes.remove("r:"+register); }
        void intersect(Requirements other) {
            for(String k:new ArrayList<>(bytes.keySet())) {
                BitSet b=bytes.get(k), o=other.bytes.get(k);
                if(o==null) bytes.remove(k); else { b.and(o); if(b.isEmpty()) bytes.remove(k); }
            }
        }
    }
    private record FrameDepth(String base, Depth depth) { }
    private static final class State {
        Requirements required=new Requirements();
        List<FrameDepth> stack=List.of();
        List<Restore> restore=List.of();
        boolean pointerUnknown;
        State copy() { var r=new State(); r.required=required.copy(); r.stack=stack; r.restore=restore; r.pointerUnknown=pointerUnknown; return r; }
        static State returnState(Abi abi) {
            var s=new State(); s.stack=List.of(new FrameDepth("r:"+abi.stackPointer(),Depth.zero()));
            s.restore=abi.preserved().stream().sorted().map(Restore::identity).toList(); return s;
        }
        static State unknownBoundary() { var s=new State(); s.pointerUnknown=true; return s; }
    }
    private static State join(List<State> successors) {
        var result=successors.get(0).copy();
        var depths=new ArrayList<FrameDepth>(); var restores=new ArrayList<Restore>();
        for(int i=0;i<successors.size();i++) {
            State s=successors.get(i); if(i>0) result.required.intersect(s.required);
            result.pointerUnknown|=s.pointerUnknown; depths.addAll(s.stack); restores.addAll(s.restore);
        }
        result.stack=mergeFrameDepths(depths); result.restore=AbstractDomains.mergeRestores(restores,LIMIT);
        return result;
    }

    private static List<FrameDepth> mergeFrameDepths(Collection<FrameDepth> input) {
        var groups=new TreeMap<String,List<Depth>>();
        for(FrameDepth f:input) groups.computeIfAbsent(f.base(),k->new ArrayList<>()).add(f.depth());
        var result=new ArrayList<FrameDepth>();
        groups.forEach((base,values)->AbstractDomains.mergeDepths(values,LIMIT).forEach(d->result.add(new FrameDepth(base,d))));
        if(result.size()>LIMIT) {
            result.sort(Comparator.comparingLong((FrameDepth f)->f.depth().count()).thenComparing(FrameDepth::base)
                .thenComparing(f->f.depth().kind()).thenComparingLong(f->f.depth().value()));
            long count=0; int remove=result.size()-LIMIT+1;
            for(int i=0;i<remove;i++) count=AbstractDomains.saturatingAdd(count,result.get(i).depth().count());
            result.subList(0,remove).clear(); result.add(new FrameDepth("?",Depth.unknown(count)));
        }
        return List.copyOf(result);
    }

    private static State transferInstruction(Candidate c, State after, Abi abi) {
        if(c.flow()==FlowKind.RETURN) return c.semantics().supported()?after:unknownEffects(after,abi);
        State exit=after.copy();
        if(isCall(c)) {
            for(String r:abi.returns()) exit.required.removeRegister(r);
            if(c.semantics().indirectTarget()!=null) exit.required.add(c.semantics().indirectTarget());
            Long cleanup=c.semantics().callStackAdjustment();
            if(cleanup==null) exit=applyAffineWrite(exit,Value.register(abi.stackPointer(),abi.wordSize()),null,abi);
            else if(cleanup!=0) exit=applyAffineWrite(exit,Value.register(abi.stackPointer(),abi.wordSize()),
                    new Affine("r:"+abi.stackPointer(),cleanup),abi);
        }
        if(c.flow()==FlowKind.INDIRECT_JUMP && c.semantics().indirectTarget()!=null)
            exit.required.add(c.semantics().indirectTarget());
        List<Op> ops=c.semantics().operations();
        if(!ops.isEmpty()) {
            List<Context> contexts=contexts(ops,abi);
            List<Integer> order=microOrder(ops);
            var before=new HashMap<Integer,State>();
            for(int index:order) {
                var next=new ArrayList<State>();
                for(int succ:microSuccessors(ops,index)) next.add(succ==ops.size()?exit:before.getOrDefault(succ,State.unknownBoundary()));
                State joined=next.isEmpty()?exit.copy():join(next);
                before.put(index,transferOp(ops.get(index),joined,contexts.get(index),abi));
            }
            exit=before.getOrDefault(0,State.unknownBoundary());
        }
        if(!c.semantics().supported()) exit=unknownEffects(exit,abi);
        return exit;
    }

    private static State transferOp(Op op, State after, Context context, Abi abi) {
        State s=after.copy(); String code=op.opcode(); Value output=op.output(); List<Value> in=op.inputs();
        if(code.equals("BRANCH") || code.equals("CBRANCH")) return s;
        if(code.equals("UNKNOWN") || code.equals("CALLOTHER") || code.equals("INDIRECT") || code.equals("MULTIEQUAL"))
            return unknownEffects(s,abi);
        boolean needed=s.required.discharge(output);
        if(code.equals("LOAD")) {
            if(in.size()>1) s.required.add(in.get(1));
        } else if(code.equals("STORE")) {
            if(in.size()>1) s.required.add(in.get(1));
        } else if(needed && !isZeroing(op)) for(Value v:in) s.required.add(v);

        Affine expression=affine(op);
        // Stack coordinates and saved-memory coordinates are changed before
        // chasing register assignment sources through the current micro-op.
        if(output!=null) s=applyAffineWrite(s,output,expression,abi);
        var restores=new ArrayList<Restore>();
        List<StackSlot> memory=code.equals("LOAD") || code.equals("STORE")
                ? context.slots(in.size()>1?in.get(1):null,abi) : List.of();
        for(Restore r:s.restore) {
            Restore transformed=r;
            if(code.equals("STORE") && r.kind()==SourceKind.STACK && in.size()>2) {
                boolean matches=memory.stream().anyMatch(slot->sameSlot(slot,r.slot()));
                if(matches) {
                    Value value=in.get(2);
                    transformed=isWhole(value)?new Restore(SourceKind.REGISTER,restoreName(value),r.slot(),r.destination(),r.count())
                            :Restore.unknown(r.destination(),r.count());
                } else if(memory.isEmpty()) transformed=Restore.unknown(r.destination(),r.count());
            } else if(output!=null && r.kind()==SourceKind.REGISTER && restoreMatches(r.register(),output)) {
                if(!isWhole(output)) transformed=Restore.unknown(r.destination(),r.count());
                else if(code.equals("COPY") && in.size()==1 && isWhole(in.get(0)))
                    transformed=new Restore(SourceKind.REGISTER,restoreName(in.get(0)),r.slot(),r.destination(),r.count());
                else if(code.equals("LOAD") && !memory.isEmpty())
                    transformed=new Restore(SourceKind.STACK,"",memory.get(0),r.destination(),r.count());
                else transformed=Restore.unknown(r.destination(),r.count());
            }
            restores.add(transformed);
        }
        s.restore=AbstractDomains.mergeRestores(restores,LIMIT);
        return s;
    }

    private static State applyAffineWrite(State state, Value output, Affine expression, Abi abi) {
        State s=state.copy(); String out=key(output);
        var stack=new ArrayList<FrameDepth>();
        for(FrameDepth f:s.stack) {
            if(!f.base().equals(out)) stack.add(f);
            else if(isWhole(output) && expression!=null) {
                Depth d=AbstractDomains.shiftDepths(List.of(f.depth()),expression.delta()).get(0);
                stack.add(new FrameDepth(expression.base(),d));
            } else stack.add(new FrameDepth("?",Depth.unknown(f.depth().count())));
        }
        s.stack=mergeFrameDepths(stack);
        var restores=new ArrayList<Restore>();
        for(Restore r:s.restore) {
            StackSlot slot=r.slot();
            if(slot!=null && slot.base().equals(out)) {
                if(!isWhole(output) || expression==null) { restores.add(Restore.unknown(r.destination(),r.count())); continue; }
                try { slot=new StackSlot(expression.base(),Math.addExact(slot.offset(),expression.delta()),slot.aggregate()); }
                catch(ArithmeticException overflow) { restores.add(Restore.unknown(r.destination(),r.count())); continue; }
            }
            restores.add(new Restore(r.kind(),r.register(),slot,r.destination(),r.count()));
        }
        s.restore=restores; return s;
    }

    private static boolean restoreMatches(String source, Value output) { return source.equals(restoreName(output)); }
    private static boolean isWhole(Value value) { return value!=null && (value.kind()==Kind.UNIQUE
            || value.kind()==Kind.REGISTER && value.fullRegister()); }
    private static String restoreName(Value value) { return value.kind()==Kind.REGISTER?value.name():key(value); }
    private static String key(Value value) { return switch(value.kind()) {
        case REGISTER->"r:"+value.name(); case UNIQUE->"u:"+value.name(); case CONSTANT->"c:"+value.constant(); case MEMORY->"m:"+value.name(); }; }
    private static boolean sameSlot(StackSlot a, StackSlot b) {
        return a!=null && b!=null && !a.aggregate() && !b.aggregate() && a.base().equals(b.base()) && a.offset()==b.offset();
    }
    private static boolean isZeroing(Op op) {
        List<Value> in=op.inputs();
        return (op.opcode().equals("INT_XOR") || op.opcode().equals("INT_SUB")) && in.size()==2 && in.get(0).equals(in.get(1))
            || op.opcode().equals("INT_AND") && in.stream().anyMatch(v->v.kind()==Kind.CONSTANT && v.constant()==0);
    }
    private record Affine(String base,long delta) { }
    private static Affine affine(Op op) {
        List<Value> in=op.inputs();
        if(op.opcode().equals("COPY") && in.size()==1 && isWhole(in.get(0))) return new Affine(key(in.get(0)),0);
        if(in.size()!=2 || !op.opcode().equals("INT_ADD") && !op.opcode().equals("INT_SUB")) return null;
        Value first=in.get(0), second=in.get(1);
        if(op.opcode().equals("INT_ADD") && first.kind()==Kind.CONSTANT) { Value t=first;first=second;second=t; }
        if(!isWhole(first) || second.kind()!=Kind.CONSTANT) return null;
        long delta=signed(second);
        try { if(op.opcode().equals("INT_SUB")) delta=Math.negateExact(delta); }
        catch(ArithmeticException overflow) { return null; }
        return new Affine(key(first),delta);
    }
    private static long signed(Value v) { int bits=v.size()*8; return bits>=64?v.constant():(v.constant()<<(64-bits))>>(64-bits); }

    private static final class Context {
        final Map<String,Affine> expressions;
        final boolean unknownDefault;
        Context(Map<String,Affine> expressions) { this(expressions,false); }
        Context(Map<String,Affine> expressions,boolean unknownDefault) {
            this.expressions=new HashMap<>(expressions);this.unknownDefault=unknownDefault;
        }
        Affine resolveKey(String key) {
            return expressions.containsKey(key)?expressions.get(key):
                !unknownDefault && key.startsWith("r:")?new Affine(key,0):null;
        }
        Affine resolve(Value value) {
            if(value==null || value.kind()==Kind.CONSTANT || value.kind()==Kind.MEMORY) return null;
            String k=key(value);
            if(expressions.containsKey(k)) return expressions.get(k);
            return !unknownDefault && value.kind()==Kind.REGISTER && value.fullRegister()?new Affine(k,0):null;
        }
        List<StackSlot> slots(Value address,Abi abi) {
            Affine target=resolve(address); if(target==null) return List.of();
            var slots=new ArrayList<StackSlot>();
            for(String base:List.of(abi.stackPointer(),abi.framePointer())) {
                Affine current=resolve(Value.register(base,abi.wordSize()));
                if(current!=null && current.base().equals(target.base())) {
                    try { slots.add(new StackSlot("r:"+base,Math.subtractExact(target.delta(),current.delta()),false)); }
                    catch(ArithmeticException ignored) { }
                }
            }
            return slots;
        }
    }
    private static List<Context> contexts(List<Op> ops,Abi abi) {
        // Join actual local predecessors. Sequentially replaying the P-code
        // array would invent aliases through an untaken internal branch.
        Map<Integer,List<Integer>> predecessors=new HashMap<>();
        for(int i=0;i<ops.size();i++) for(int next:microSuccessors(ops,i))
            if(next<ops.size()) predecessors.computeIfAbsent(next,k->new ArrayList<>()).add(i);
        var order=new ArrayList<>(microOrder(ops));Collections.reverse(order);
        Map<Integer,Context> before=new HashMap<>(),after=new HashMap<>();
        for(int index:order) {
            var incoming=new ArrayList<Context>();
            if(index==0) incoming.add(new Context(Map.of()));
            for(int pred:predecessors.getOrDefault(index,List.of()))
                incoming.add(after.getOrDefault(pred,new Context(Map.of(),true)));
            Context context=joinContexts(incoming);before.put(index,context);
            Op op=ops.get(index);Map<String,Affine> env=new HashMap<>(context.expressions);
            Value out=op.output();
            if(out!=null) {
                Affine expression=affine(op), resolved=null;
                if(expression!=null) {
                    Affine source=context.resolveKey(expression.base());
                    if(source!=null) try { resolved=new Affine(source.base(),Math.addExact(source.delta(),expression.delta())); }
                        catch(ArithmeticException ignored) { }
                }
                env.put(key(out),isWhole(out)?resolved:null);
            }
            boolean unknown=context.unknownDefault;
            if(op.opcode().equals("UNKNOWN") || op.opcode().equals("CALLOTHER")) { env.clear();unknown=true; }
            after.put(index,new Context(env,unknown));
        }
        var result=new ArrayList<Context>();
        for(int i=0;i<ops.size();i++) result.add(before.getOrDefault(i,new Context(Map.of(),true)));
        return result;
    }
    private static Context joinContexts(List<Context> inputs) {
        if(inputs.isEmpty()) return new Context(Map.of(),true);
        Set<String> keys=new HashSet<>();for(Context c:inputs) keys.addAll(c.expressions.keySet());
        Map<String,Affine> joined=new HashMap<>();
        for(String key:keys) {
            Affine value=inputs.get(0).resolveKey(key);
            for(int i=1;i<inputs.size();i++) if(!Objects.equals(value,inputs.get(i).resolveKey(key))) { value=null;break; }
            joined.put(key,value);
        }
        return new Context(joined,inputs.stream().anyMatch(c->c.unknownDefault));
    }

    private static State unknownEffects(State s,Abi abi) {
        State result=s.copy(); result.pointerUnknown=true; result.required=new Requirements();
        result.stack=List.of(new FrameDepth("?",Depth.unknown()));
        result.restore=abi.preserved().stream().sorted().map(r->Restore.unknown(r,1)).toList();
        return result;
    }
    private static State normalizeBoundary(State state,Abi abi) {
        State s=state.copy();
        for(String key:new ArrayList<>(s.required.bytes.keySet())) if(!key.startsWith("r:")) {
            s.required.bytes.remove(key); s.pointerUnknown=true;
        }
        var stack=new ArrayList<FrameDepth>();
        for(FrameDepth f:s.stack) if(f.base().equals("r:"+abi.stackPointer()) || f.base().equals("r:"+abi.framePointer())) stack.add(f);
            else stack.add(new FrameDepth("?",Depth.unknown(f.depth().count())));
        s.stack=mergeFrameDepths(stack);
        var restores=new ArrayList<Restore>();
        for(Restore r:s.restore) {
            boolean badSource=r.kind()==SourceKind.REGISTER && (r.register().startsWith("u:") || r.register().startsWith("m:"));
            boolean badSlot=r.slot()!=null && !r.slot().base().equals("r:"+abi.stackPointer()) && !r.slot().base().equals("r:"+abi.framePointer());
            restores.add(badSource || badSlot?Restore.unknown(r.destination(),r.count()):r);
        }
        s.restore=AbstractDomains.mergeRestores(restores,LIMIT); return s;
    }
    private static Facts toFacts(Candidate c,State s,Abi abi) {
        Set<String> required=new TreeSet<>(); for(String key:s.required.bytes.keySet()) required.add(key.substring(2));
        var depths=new ArrayList<Depth>();
        for(FrameDepth f:s.stack) depths.add(f.base().equals("r:"+abi.stackPointer())?f.depth():Depth.unknown(f.depth().count()));
        List<Depth> merged=AbstractDomains.mergeDepths(depths,LIMIT);
        Map<String,List<Restore>> restores=new TreeMap<>();
        for(Restore r:s.restore) restores.computeIfAbsent(r.destination(),k->new ArrayList<>()).add(r);
        boolean pointer=abi.entryDefined().containsAll(required);
        boolean stack=merged.stream().anyMatch(d->d.kind()==DepthKind.UNKNOWN || d.kind()==DepthKind.CONCRETE && d.value()==0);
        boolean registers=AbstractDomains.registersCompatible(s.restore);
        boolean concrete=merged.stream().anyMatch(d->d.kind()==DepthKind.CONCRETE && d.value()==0)
                || s.restore.stream().anyMatch(r->r.kind()==SourceKind.REGISTER && r.register().equals(r.destination()) && r.slot()!=null);
        boolean entry=pointer && stack && registers && concrete && c.semantics().supported();
        String note=!c.semantics().supported()?"unsupported P-code effects":s.pointerUnknown?"unknown successor or effect":"";
        return new Facts(required,s.pointerUnknown,merged,restores,pointer,stack,registers,concrete,entry,note);
    }

    private static List<Integer> microSuccessors(List<Op> ops,int index) {
        Op op=ops.get(index); int next=index+1;
        if(op.opcode().equals("BRANCH") && op.branchTarget()>=0) return List.of(Math.min(op.branchTarget(),ops.size()));
        if(op.opcode().equals("CBRANCH") && op.branchTarget()>=0) {
            int target=Math.min(op.branchTarget(),ops.size()); return target==next?List.of(next):List.of(target,next);
        }
        return List.of(next);
    }
    private static List<Integer> microOrder(List<Op> ops) {
        var order=new ArrayList<Integer>(); var seen=new HashSet<Integer>();
        var stack=new ArrayDeque<int[]>(); stack.push(new int[]{0,0}); seen.add(0);
        while(!stack.isEmpty()) {
            int[] top=stack.peek(); List<Integer> succ=microSuccessors(ops,top[0]);
            if(top[1]<succ.size()) { int next=succ.get(top[1]++); if(next<ops.size() && seen.add(next)) stack.push(new int[]{next,0}); }
            else { order.add(top[0]); stack.pop(); }
        }
        return order;
    }

    /** Iterative Tarjan: SCCs are emitted with successor components first. */
    private static List<List<Site>> components(Set<Site> nodes,Map<Site,List<Site>> edges,Runnable cancel) {
        Map<Site,Integer> index=new HashMap<>(),low=new HashMap<>(); Set<Site> active=new HashSet<>();
        var members=new ArrayDeque<Site>(); var result=new ArrayList<List<Site>>(); int counter=0;
        record Frame(Site site,Iterator<Site> successors) { }
        var dfs=new ArrayDeque<Frame>();
        for(Site root:new TreeSet<>(nodes)) {
            if(index.containsKey(root)) continue;
            index.put(root,counter);low.put(root,counter++);members.push(root);active.add(root);
            dfs.push(new Frame(root,edges.getOrDefault(root,List.of()).iterator()));
            while(!dfs.isEmpty()) {
                cancel.run(); Frame frame=dfs.peek(); Site node=frame.site();
                if(frame.successors().hasNext()) {
                    Site next=frame.successors().next(); if(!nodes.contains(next)) continue;
                    if(!index.containsKey(next)) {
                        index.put(next,counter);low.put(next,counter++);members.push(next);active.add(next);
                        dfs.push(new Frame(next,edges.getOrDefault(next,List.of()).iterator()));
                    } else if(active.contains(next)) low.put(node,Math.min(low.get(node),index.get(next)));
                } else {
                    dfs.pop();
                    if(!dfs.isEmpty()) { Site parent=dfs.peek().site(); low.put(parent,Math.min(low.get(parent),low.get(node))); }
                    if(low.get(node).equals(index.get(node))) {
                        var component=new ArrayList<Site>(); Site item;
                        do { item=members.pop();active.remove(item);component.add(item); } while(!item.equals(node));
                        component.sort(Comparator.naturalOrder());result.add(component);
                    }
                }
            }
        }
        return result;
    }
    /** RPO of reversed internal edges, rooted at exits, fixes a deterministic one-pass loop order. */
    private static List<Site> backwardOrder(List<Site> component,Map<Site,List<Site>> edges,Runnable cancel) {
        if(component.size()==1) return component;
        Set<Site> set=new HashSet<>(component); Map<Site,List<Site>> reverse=new HashMap<>();
        var roots=new ArrayList<Site>();
        for(Site site:component) {
            List<Site> succ=edges.getOrDefault(site,List.of());
            if(succ.isEmpty() || succ.stream().anyMatch(s->!set.contains(s))) roots.add(site);
            for(Site next:succ) if(set.contains(next)) reverse.computeIfAbsent(next,k->new ArrayList<>()).add(site);
        }
        roots.addAll(component);reverse.values().forEach(v->v.sort(Comparator.naturalOrder()));
        Set<Site> seen=new HashSet<>(); var post=new ArrayList<Site>();
        record Frame(Site site,Iterator<Site> next) { }
        var dfs=new ArrayDeque<Frame>();
        for(Site root:roots) {
            if(!seen.add(root)) continue;dfs.push(new Frame(root,reverse.getOrDefault(root,List.of()).iterator()));
            while(!dfs.isEmpty()) {
                cancel.run(); Frame frame=dfs.peek();
                if(frame.next().hasNext()) { Site next=frame.next().next();if(seen.add(next)) dfs.push(new Frame(next,reverse.getOrDefault(next,List.of()).iterator())); }
                else { post.add(frame.site());dfs.pop(); }
            }
        }
        Collections.reverse(post);return post;
    }
}
