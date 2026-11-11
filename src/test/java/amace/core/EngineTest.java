package amace.core;

import java.util.*;
import amace.core.Semantics.*;
import amace.core.AbstractDomains.*;

/** Golden examples of AMACE equations plus SLEIGH adaptation regressions. */
public final class EngineTest {
    private static int checks;
    private static final Abi ABI=Abi.SYSV_X64;
    private static final Value SP=Value.register("rsp",8),BP=Value.register("rbp",8),
        AX=Value.register("rax",8),BX=Value.register("rbx",8),CX=Value.register("rcx",8),SPACE=Value.constant(0,8);
    private static Site s(long n) { return new Site("ram",n); }
    private static Value c(long n) { return Value.constant(n,8); }
    private static Semantics sem(Op...ops) { return new Semantics(List.of(ops),true,null,0L); }
    private static Op op(String name,Value out,Value...in) { return new Op(name,out,List.of(in)); }
    private static Candidate n(long at,long next,Op...ops) {
        return new Candidate(s(at),new byte[]{0x40},"test","",FlowKind.NORMAL,List.of(),s(next),sem(ops));
    }
    private static Candidate ret(long at) {
        return new Candidate(s(at),new byte[]{(byte)0xc3},"ret","",FlowKind.RETURN,List.of(),null,Semantics.identity());
    }
    private static Candidate call(long at,long target,long next) {
        return new Candidate(s(at),new byte[]{(byte)0xe8},"call","",FlowKind.CALL,List.of(s(target)),s(next),Semantics.identity());
    }
    private static Candidate branch(long at,long target,long fallthrough) {
        return new Candidate(s(at),new byte[]{0x75},"jne","",FlowKind.CONDITIONAL_JUMP,List.of(s(target)),s(fallthrough),Semantics.identity());
    }
    private static AmaceEngine.Analysis analyze(Candidate...nodes) {
        return new AmaceEngine().analyze(List.of(nodes),ABI,Set.of(),Set.of(s(0)),()->{});
    }
    private static void check(boolean condition,String message) {
        checks++;if(!condition) throw new AssertionError(message);
    }
    private static boolean zero(AmaceEngine.Facts f) {
        return f.depths().stream().anyMatch(d->d.kind()==DepthKind.CONCRETE && d.value()==0);
    }
    private static Candidate push(long at,long next,Value reg) {
        Value t=Value.temporary(at+1000,8);
        return n(at,next,op("COPY",t,reg),op("INT_SUB",SP,SP,c(8)),op("STORE",null,SPACE,SP,t));
    }
    private static Candidate pop(long at,long next,Value reg) {
        Value t=Value.temporary(at+2000,8);
        return n(at,next,op("LOAD",t,SPACE,SP),op("INT_ADD",SP,SP,c(8)),op("COPY",reg,t));
    }

    public static void main(String[] args) {
        pointerEquations(); partialRegisters(); branchIntersection(); stackAndSaveRestore(); tableFour();
        framePointerAlloca(); callBoundaries(); nonReturningCalls(); unknownAndLoops(); signed32Stack();
        microControlFlow(); fidelityAndOrder(); linearChain();
        System.out.println("EngineTest: "+checks+" checks passed");
    }
    private static void pointerEquations() {
        Candidate load=n(1,2,op("LOAD",BX,SPACE,AX));
        var result=analyze(n(0,1,op("COPY",AX,c(0x1000))),load,ret(2));
        check(result.facts().get(s(1)).requiredRegisters().equals(Set.of("rax")),"dereference requires its address register");
        check(result.facts().get(s(0)).requiredRegisters().isEmpty(),"constant assignment discharges pointer requirement");
        result=analyze(n(0,1,op("INT_ADD",AX,CX,c(8))),load,ret(2));
        check(result.facts().get(s(0)).requiredRegisters().equals(Set.of("rcx")),"arithmetic propagates required input");
        result=analyze(n(0,1,op("INT_XOR",AX,AX,AX)),load,ret(2));
        check(result.facts().get(s(0)).requiredRegisters().isEmpty(),"self zeroing is a definition");
        result=analyze(n(0,1,op("LOAD",AX,SPACE,CX)),load,ret(2));
        check(result.facts().get(s(0)).requiredRegisters().equals(Set.of("rcx")),"loaded value discharges requirement while its address is required");
        Value indirect=Value.temporary(99,8);
        Candidate jump=new Candidate(s(0),new byte[]{(byte)0xff},"jmp","",FlowKind.INDIRECT_JUMP,List.of(),null,
            new Semantics(List.of(op("COPY",indirect,AX)),true,indirect,0L));
        check(analyze(jump).facts().get(s(0)).requiredRegisters().equals(Set.of("rax")),"indirect jump pointer is required");
    }
    private static void partialRegisters() {
        Value al=new Value(Kind.REGISTER,"rax",0,1,8,0);
        Candidate load=n(1,2,op("LOAD",BX,SPACE,AX));
        var result=analyze(n(0,1,op("COPY",al,Value.constant(1,1))),load,ret(2));
        check(result.facts().get(s(0)).requiredRegisters().equals(Set.of("rax")),"AL definition cannot define full RAX pointer");
        Value eax=new Value(Kind.REGISTER,"rax",0,4,8,0);
        result=analyze(n(0,1,op("COPY",eax,Value.constant(1,4)),op("INT_ZEXT",AX,eax)),load,ret(2));
        check(result.facts().get(s(0)).requiredRegisters().isEmpty(),"EAX then zero extension defines full RAX");
    }
    private static void branchIntersection() {
        var result=analyze(branch(0,10,1),n(1,2,op("STORE",null,SPACE,AX,c(1))),ret(2),
            n(10,11,op("STORE",null,SPACE,CX,c(1))),ret(11));
        check(result.facts().get(s(0)).requiredRegisters().isEmpty(),"conditional merge intersects required registers");
        result=analyze(branch(0,10,1),n(1,2,op("STORE",null,SPACE,AX,c(1))),ret(2),
            n(10,11,op("STORE",null,SPACE,AX,c(1))),ret(11));
        check(result.facts().get(s(0)).requiredRegisters().equals(Set.of("rax")),"both branch requirements retained");
    }
    private static void stackAndSaveRestore() {
        var result=analyze(push(0,1,BX),n(1,2,op("INT_XOR",AX,AX,AX)),pop(2,3,BX),ret(3));
        var root=result.facts().get(s(0));
        check(zero(root),"push/pop restores zero entry depth");
        check(root.depths().get(0).maxDepth()==8,"maximum stack depth records pushed word");
        check(root.registersCompatible(),"matching save/restore preserves register");
        check(root.restorations().get("rbx").stream().anyMatch(r->r.kind()==SourceKind.REGISTER
            && r.register().equals("rbx") && r.slot()!=null && r.slot().offset()==-8),"active save uses pre-push relative address");
        result=analyze(n(0,1,op("COPY",BX,CX)),ret(1));
        check(!result.facts().get(s(0)).registersCompatible(),"restoring from wrong register is mismatch");
        check(result.facts().get(s(0)).depths().get(0).value()==0,"register move leaves stack depth unaffected");
    }
    private static void framePointerAlloca() {
        Value a=Value.temporary(500,8);
        var result=analyze(push(0,1,BP),push(1,2,BX),n(2,3,op("COPY",BP,SP)),
            n(3,4,op("INT_ADD",BP,BP,c(8))),n(4,5,op("INT_SUB",SP,SP,CX)),
            n(5,6,op("INT_ADD",a,BP,c(-8)),op("LOAD",BX,SPACE,a)),
            n(6,7,op("COPY",SP,BP)),pop(7,8,BP),ret(8));
        check(zero(result.facts().get(s(0))),"BP coordinate recovers stack across dynamic alloca");
        check(result.facts().get(s(0)).registersCompatible(),"SP/BP-relative save restoration survives alloca");
        check(result.facts().get(s(0)).restorations().get("rbx").stream().anyMatch(r->r.kind()==SourceKind.REGISTER
            && r.register().equals("rbx") && r.slot()!=null),"BP-relative load chains to original save");
    }
    private static void tableFour() {
        Value si=Value.register("rsi",8);
        Candidate allocate=n(11,12,op("INT_SUB",SP,SP,c(32)));
        Candidate deallocate=n(12,13,op("INT_ADD",SP,SP,c(48)));
        var result=analyze(branch(0,10,1),push(1,2,BX),push(2,3,si),branch(3,11,4),
            pop(4,5,si),pop(5,6,BX),ret(6),call(10,100,11),allocate,deallocate,ret(13));
        List<Depth> depths=result.facts().get(s(0)).depths();
        check(depths.contains(Depth.concrete(0,48,2)),"paper Table4: two balanced paths and max depth48");
        check(depths.contains(Depth.concrete(16,48,1)),"paper Table4: one unbalanced path retained separately");
        check(result.facts().get(s(0)).stackCompatible(),"one nonzero path does not suppress valid zero-depth evidence");
    }
    private static void callBoundaries() {
        var result=analyze(call(0,20,1),n(1,2,op("LOAD",BX,SPACE,AX)),ret(2),ret(20));
        check(result.facts().get(s(0)).requiredRegisters().isEmpty(),"call discharges ABI return registers");
        check(zero(result.facts().get(s(0))),"atomic call adds no return-address stack push");
        check(result.noReturnCalls().isEmpty(),"ordinary call followed by return stays returning");
        check(!result.inferredEntries().contains(s(20)),"bare RET is not an invented function entry");
        Candidate cleanupUnknown=new Candidate(s(1),new byte[]{(byte)0xe8},"call","",FlowKind.CALL,List.of(s(100)),s(2),
            new Semantics(List.of(),true,null,null));
        result=analyze(push(0,1,BX),cleanupUnknown,pop(2,3,BX),ret(3));
        check(!result.facts().get(s(0)).concreteEvidence(),"unknown callee cleanup invalidates SP-relative save coordinates");
    }
    private static void nonReturningCalls() {
        Candidate halt=new Candidate(s(20),new byte[]{(byte)0xf4},"hlt","",FlowKind.HALT,List.of(),null,Semantics.identity());
        var result=analyze(call(0,20,1),ret(1),halt);
        check(result.noReturnCalls().contains(s(0)),"callee all-exits halt implies nonreturning call");
        result=new AmaceEngine().analyze(List.of(call(0,1000,1),ret(1)),ABI,Set.of(s(1000)),Set.of(s(0)),()->{});
        check(result.noReturnCalls().contains(s(0)),"known catalog target marks callsite");
        Candidate indirect=new Candidate(s(21),new byte[]{(byte)0xff},"jmp","",FlowKind.INDIRECT_JUMP,List.of(),null,Semantics.identity());
        result=analyze(call(0,20,1),ret(1),branch(20,22,21),indirect,
            new Candidate(s(22),new byte[]{(byte)0xf4},"hlt","",FlowKind.HALT,List.of(),null,Semantics.identity()));
        check(result.noReturnCalls().isEmpty(),"unresolved indirect exit prevents nonreturn proof");
    }
    private static void unknownAndLoops() {
        Candidate unknown=new Candidate(s(0),new byte[]{0x40},"unknown","",FlowKind.NORMAL,List.of(),s(1),Semantics.unknown());
        var result=analyze(unknown,ret(1));
        check(!result.facts().get(s(0)).concreteEvidence(),"unknown operation gives no positive entry evidence");
        check(!result.facts().get(s(0)).entryCandidate(),"unsupported instruction cannot become inferred entry");
        Candidate loop=new Candidate(s(0),new byte[]{(byte)0xeb},"jmp","",FlowKind.JUMP,List.of(s(0)),null,Semantics.identity());
        result=analyze(loop);
        check(!result.facts().get(s(0)).entryCandidate(),"SCC with no terminal remains unknown");
        check(result.noReturnCalls().isEmpty(),"unresolved loop does not prove no-return calls");
        Candidate iret=new Candidate(s(1),new byte[]{(byte)0xcf},"iret","",FlowKind.RETURN,List.of(),null,Semantics.unknown());
        result=analyze(n(0,1),iret);
        check(!result.facts().get(s(0)).concreteEvidence(),"unsupported return cannot leak identity CSR and zero stack evidence");
    }
    private static void signed32Stack() {
        Value esp=Value.register("esp",4),ebx=Value.register("ebx",4),t=Value.temporary(0x900,4);
        Candidate push=n(0,1,op("COPY",t,ebx),op("INT_ADD",esp,esp,Value.constant(0xffff_fffcL,4)),op("STORE",null,SPACE,esp,t));
        Candidate pop=n(1,2,op("LOAD",t,SPACE,esp),op("INT_ADD",esp,esp,Value.constant(4,4)),op("COPY",ebx,t));
        var result=new AmaceEngine().analyze(List.of(push,pop,ret(2)),Abi.SYSV_X86,Set.of(),Set.of(s(0)),()->{});
        check(zero(result.facts().get(s(0))),"32-bit signed immediate stack decrement is normalized");
        check(result.facts().get(s(0)).registersCompatible(),"32-bit save restore matches its stack coordinates");
    }
    private static void microControlFlow() {
        Value address=Value.temporary(800,8);
        Candidate local=n(0,1,
            new Op("CBRANCH",null,List.of(c(1)),3),
            op("INT_ADD",address,SP,c(0)),new Op("BRANCH",null,List.of(),4),
            op("INT_ADD",address,SP,c(8)),op("LOAD",BX,SPACE,address));
        var result=analyze(local,ret(1));
        check(result.facts().get(s(0)).restorations().get("rbx").stream().allMatch(r->r.kind()==SourceKind.UNKNOWN),
            "different local paths cannot invent a single stack alias");
        Candidate localPointer=n(0,1,new Op("CBRANCH",null,List.of(c(1)),3),
            op("STORE",null,SPACE,AX,c(1)),new Op("BRANCH",null,List.of(),4),op("STORE",null,SPACE,CX,c(1)));
        result=analyze(localPointer,ret(1));
        check(result.facts().get(s(0)).requiredRegisters().isEmpty(),"internal P-code conditional uses intersection of address requirements");
    }
    private static void fidelityAndOrder() {
        List<Candidate> intended=List.of(push(0,2,BX),pop(2,4,BX),ret(4));
        var first=new AmaceEngine().analyze(intended,ABI,Set.of(),Set.of(s(0)),()->{});
        var polluted=new ArrayList<>(intended);polluted.add(n(1,2,op("COPY",BX,CX)));
        var second=new AmaceEngine().analyze(polluted,ABI,Set.of(),Set.of(s(0)),()->{});
        for(Candidate c:intended) check(first.facts().get(c.site()).equals(second.facts().get(c.site())),"unintended predecessor cannot pollute intended facts");
        Collections.reverse(polluted);
        var reverse=new AmaceEngine().analyze(polluted,ABI,Set.of(),Set.of(s(0)),()->{});
        check(reverse.equals(second),"analysis is independent of candidate enumeration order");
    }
    private static void linearChain() {
        var nodes=new ArrayList<Candidate>();for(int i=0;i<20000;i++) nodes.add(n(i,i+1));nodes.add(ret(20000));
        var result=new AmaceEngine().analyze(nodes,ABI,Set.of(),Set.of(s(0)),()->{});
        check(zero(result.facts().get(s(0))),"large graph is evaluated without recursive stack overflow");
        int[] count={0};
        try { new AmaceEngine().analyze(nodes,ABI,Set.of(),()->{if(++count[0]==100) throw new IllegalStateException("cancel");});
            throw new AssertionError("cancellation must propagate"); }
        catch(IllegalStateException expected) { check(expected.getMessage().equals("cancel"),"cancellation propagated"); }
    }
}
