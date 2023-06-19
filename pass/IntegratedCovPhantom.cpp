
#include "config.h"
#include "utils.h"
#include "debug.h"

#include <stack>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <unistd.h>

#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Mem2Reg.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/ADT/SCCIterator.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
#include "llvm/Transforms/Utils/Mem2Reg.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/Analysis/CFG.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/MemorySSA.h"
#include "llvm/InitializePasses.h"
#include <vector>

#include <ostream>

using namespace llvm;



static cl::opt<bool> StrictCTF(
    "strict-CTF", cl::init(true), cl::Hidden,
    cl::desc("Only analyze dependency for pointer when getting nested if entry."));

static cl::opt<bool> StrictMemWrite(
    "strict-mem-write", cl::init(true), cl::Hidden,
    cl::desc("Whether of not append those function calls into side effect constraints."));

static cl::opt<u8> LoopConsLevel(
    "loop-cons-level", cl::init(1), cl::Hidden,
    cl::desc("The level of loop constraint in the process of insnHoist in MutateIf pass, \n"
             "0 for permitting limited LICM, \n"
             "1 for crossing loop forbidden, \n"
             "2 for crossing loop exitings/latches forbidden."));

static cl::opt<bool> HoistCallInst(
    "hoist-call", cl::init(false), cl::Hidden,
    cl::desc("Extraly hoist those call instructions invoking readonly functions."));

static cl::opt<bool> IntegMode(
    "IntegMode", cl::init(false), cl::Hidden,
    cl::desc("Integrated Mode"));

static cl::opt<bool> PhantomMode(
    "PhantomMode", cl::init(false), cl::Hidden,
    cl::desc("Mutated If Mode"));

static cl::opt<bool> SourceMode(
    "SourceMode", cl::init(false), cl::Hidden,
    cl::desc("Source Mode"));

static cl::opt<bool> PinMode(
    "PinMode", cl::init(false), cl::Hidden,
    cl::desc("Pin DTA Mode"));

static cl::opt<bool> LafMode(
    "LafMode", cl::init(false), cl::Hidden,
    cl::desc("equivalent to AFL-lafintel but save all the BB id."));
static cl::opt<bool> AFLMode(
    "AFLMode", cl::init(false), cl::Hidden,
    cl::desc("equivalent to AFL llvm mode."));
static cl::opt<bool> NoLaf(
    "NoLaf", cl::init(false), cl::Hidden,
    cl::desc("do not split the compares."));

#define addInsn2set(set, insn)                           \
    {                                                    \
        set.insert(insn);                                \
        Value *val = insn;                               \
        while (CastInst *cast = dyn_cast<CastInst>(val)) \
        {                                                \
            val = cast->getOperand(0);                   \
            set.insert(val);                             \
        }                                                \
    }

// static void inline addDep2Set(SmallPtrSetImpl<Value *> &set, Value *val)
// {
//     if (BinaryOperator *bo = dyn_cast<BinaryOperator>(val))
//     {
//         set.insert(bo);
//         addDep2Set(set, bo->getOperand(0));
//         addDep2Set(set, bo->getOperand(1));
//     }
//     else
//     {
//         addInsn2set(set, val)
//     }
// }

#define addInsn2vec(vec, insn)                               \
    {                                                        \
        if (insn)                                            \
        {                                                    \
            vec.push_back(insn);                             \
            Value *val = insn;                               \
            while (CastInst *cast = dyn_cast<CastInst>(val)) \
            {                                                \
                val = cast->getOperand(0);                   \
                vec.push_back(val);                          \
            }                                                \
        }                                                    \
    }

// static void inline addDep2Vec(SmallVectorImpl<Value *> &vec, Value *val)
// {
//     if (!val)
//         return;
//     if (BinaryOperator *bo = dyn_cast<BinaryOperator>(val))
//     {
//         vec.push_back(bo);
//         addDep2Vec(vec, bo->getOperand(0));
//         addDep2Vec(vec, bo->getOperand(1));
//     }
//     else
//     {
//         addInsn2vec(vec, val)
//     }
// }


#define getEdgeId(from, to) ConstantInt::get(Int32Ty, (from >> 1) ^ to)
#define num2LLVMConstant(num) ConstantInt::get(Int32Ty, num)

static Function *covFunc, *phantomFunc, *sourceSinkFunc;
static FunctionCallee sourceDTASink, phantomDTASink;

static Type *VOID;
static IntegerType *Int1Ty;
static IntegerType *Int8Ty;
static IntegerType *Int16Ty;
static IntegerType *Int32Ty;
static IntegerType *Int64Ty;

static DominatorTree *DT;
static PostDominatorTree *PDT;
static BasicBlock *entryBB;
static LoopInfo *LI;
static MemorySSA *MSSA;

static ConstantInt *NEG_ONE_32;
static ConstantInt *SEVEN_32;
static ConstantInt *THREE_32;
static ConstantInt *ONE_32;
static ConstantInt *U255_8;
static ConstantInt *ONE_8;
static ConstantInt *TWO_8;
static ConstantInt *FULL_ONE_8;

u32 edge_id = 0;
u32 edge_num = 0;

static inline u32 next_edge_id()
{
    if (++edge_id == 0x10000)
        edge_id = 1;
    edge_num++;
    return edge_id;
}

static inline BasicBlock *getIDomBB(BasicBlock *bb)
{
    if (bb == nullptr)
        return nullptr;
    auto *DTNode = DT->operator[](bb);
    if (DTNode != nullptr)
    {
        DTNode = DTNode->getIDom();
        if (DTNode != nullptr)
        {
            return DTNode->getBlock();
        }
    }
    return nullptr;
}

static inline BasicBlock *getIPDomBB(BasicBlock *bb)
{
    if (bb == nullptr)
        return nullptr;
    auto *PDTNode = PDT->operator[](bb);
    if (PDTNode != nullptr)
    {
        PDTNode = PDTNode->getIDom();
        if (PDTNode != nullptr)
        {
            return PDTNode->getBlock();
        }
    }
    return nullptr;
}

[[maybe_unused]]
static inline BasicBlock *getICoDomBB(BasicBlock *bb)
{
    if (bb == nullptr)
        return nullptr;
    auto *PDTNode = PDT->operator[](bb);
    if (PDTNode != nullptr)
    {
        PDTNode = PDTNode->getIDom();
        if (PDTNode != nullptr)
        {
            BasicBlock *postDomBB = PDTNode->getBlock();
            return DT->dominates(bb, postDomBB) ? postDomBB : nullptr;
        }
    }
    return nullptr;
}

static inline BasicBlock *getOuterBlock(BasicBlock *srcBB, BasicBlock *topBB)
{
    
    BasicBlock *domBB = getIDomBB(srcBB);
    while (domBB != nullptr && PDT->dominates(srcBB, domBB))
    {
        srcBB = domBB;
        domBB = getIDomBB(srcBB);
    }
    if (!DT->dominates(topBB, domBB))
        domBB = nullptr;
    return domBB;
}

/**
 * return the successor one between the 2 instructions.
 * @param i1
 * @param i2
 * @return
 */
static inline Instruction *cross(Instruction *i1, Instruction *i2)
{
    if (i1 == nullptr)
        return i2;
    if (i2 == nullptr)
        return i1;
    
    return DT->dominates(i1, i2) ? i2 : i1;
}

static inline bool isTrueSuccessor(const BranchInst *branchInst,
                                   const BasicBlock *block)
{
    return DT->dominates(branchInst->getSuccessor(0), block);
}

static BasicBlock *getValidBlockInLoopConstraint(Loop *curLoop, BasicBlock *curBB, Loop *tarLoop)
{
    /**
     * curr loop {
     *      tar loop {
     *          tar_insn
     *          ...
     *      }
     *
     *      curr insn to hoist
     * }
     *
     * ------------------------
     *
     * loop or function {
     *      tar loop {
     *          tar_insn
     *          ...
     *      }
     *
     *      curr loop {
     *          insn to hoist
     *      }
     * }
     */
    
    while (tarLoop->getParentLoop() && !tarLoop->getParentLoop()->contains(curLoop))
    {
        tarLoop = tarLoop->getParentLoop();
    }

    SmallVector<BasicBlock *, 4> exitBBs;
    tarLoop->getExitBlocks(exitBBs);
    
    for (auto exitBB : exitBBs)
    {
        if (DT->dominates(exitBB, curBB))
        {
            return exitBB;
        }
    }
    return getIPDomBB(tarLoop->getHeader());
}

static BasicBlock *getBackLastDomExitingOrLatch(Loop *loop, BasicBlock *BB)
{
    BasicBlock *entry = BB;
    do
    {
        if (loop->isLoopExiting(entry) || loop->isLoopLatch(entry))
        {
            
            return BB;
        }
        BB = entry;
        entry = getIDomBB(entry);
    } while (entry && LI->getLoopFor(entry) == loop);
    return loop->getHeader();
}


static inline bool hasSideEffect(Instruction *inst)
{
    if (inst->mayWriteToMemory() || isa<PHINode>(inst)
        
        || isa<LandingPadInst>(inst) || isa<InvokeInst>(inst))
    {
        return true;
    }

    
    
    
    
    
    return false;
}

static inline MemoryAccess *findDefiningAccess(Instruction *insn)
{
    if (!insn)
        return nullptr;
    
    if (insn->mayReadOrWriteMemory())
    {
        auto mud = MSSA->getMemoryAccess(insn);
        if (mud)
        {
            auto ma = mud->getDefiningAccess();
            if (!ma)
                return nullptr;
            if (isa<MemoryPhi>(ma))
            {
                return ma;
            }
            else if (auto md = dyn_cast<MemoryDef>(ma))
            {
                auto defInst = md->getMemoryInst();
                if (!defInst)
                    return ma;
                CallInst *call = dyn_cast<CallInst>(defInst);
                if (isInWhiteList(call))
                {
                    return findDefiningAccess(call);
                }
                return ma;
            }
        }
    }
    return nullptr;
}

static inline Value *castArgType(IRBuilder<> &IRB, Value *V)
{
    Type *OpType = V->getType();
    Value *NV = V;
    if (OpType->isFloatTy())
    {
        NV = IRB.CreateFPToUI(V, Int32Ty);
        SetNoSanitize(NV);
        NV = IRB.CreateIntCast(NV, Int64Ty, false);
        SetNoSanitize(NV);
    }
    else if (OpType->isDoubleTy())
    {
        NV = IRB.CreateFPToUI(V, Int64Ty);
        SetNoSanitize(NV);
    }
    else if (OpType->isPointerTy())
    {
        NV = IRB.CreatePtrToInt(V, Int64Ty);
    }
    else
    {
        if (OpType->isIntegerTy() && OpType->getIntegerBitWidth() < 64)
        {
            NV = IRB.CreateZExt(V, Int64Ty);
        }
    }
    return NV;
}


static Instruction *insnHoist(Instruction *insn, BasicBlock *ctfHead)
{
    

    if (!insn)
        return insn;
    if (hasSideEffect(insn))
        return insn;
    if (!HoistCallInst && isa<CallInst>(insn))
        return insn;

    BasicBlock *curBB = insn->getParent();
    if (DT->dominates(curBB, ctfHead))
        return insn;

    BasicBlock *hoistBarrier = ctfHead;
    Loop *loop = LI->getLoopFor(curBB);
    if (loop)
    {
        BasicBlock *loopBarrier = nullptr;
        if (LoopConsLevel == 2)
        {
            loopBarrier = getBackLastDomExitingOrLatch(loop, insn->getParent());
        }
        else if (LoopConsLevel == 1)
        {
            loopBarrier = loop->getHeader();
        }
        if (loopBarrier)
        {
            hoistBarrier = DT->dominates(loopBarrier, hoistBarrier) ? hoistBarrier : loopBarrier;
        }
    }
    if (DT->dominates(curBB, hoistBarrier))
    {
        return insn;
    }

    Instruction *movePoint = nullptr;

    
    auto ma = findDefiningAccess(insn);

    if (ma)
    {

        if (auto mp = dyn_cast<MemoryPhi>(ma))
        {
            
            
            BasicBlock *headBB = mp->getBlock();
            if (headBB && (!hoistBarrier || DT->dominates(hoistBarrier, headBB)))
            {
                hoistBarrier = headBB;
            }
            else if (DT->dominates(insn->getParent(), headBB))
            {
                return insn;
            }
        }
        else if (auto md = dyn_cast<MemoryDef>(ma))
        {
            auto defInst = md->getMemoryInst();
            if (defInst)
            {
                defInst = insnHoist(defInst, hoistBarrier);
                movePoint = cross(movePoint, defInst);
            }
        }
    }

    for (Use &op : insn->operands())
    {
        if (Instruction *instOp = dyn_cast<Instruction>(op))
        {
            if (!DT->dominates(instOp->getParent(), hoistBarrier))
            {
                instOp = insnHoist(instOp, hoistBarrier);
            }
            movePoint = cross(movePoint, instOp);
        }
    }

    if (movePoint && DT->dominates(movePoint, insn))
    {

        BasicBlock *tarBB = movePoint->getParent();
        Loop *tarLoop = LI->getLoopFor(tarBB);
        
        if (loop && loop != tarLoop && loop->contains(tarLoop))
        {
            tarBB = getValidBlockInLoopConstraint(loop, curBB, tarLoop);
            if (DT->dominates(tarBB, curBB) && (!hoistBarrier || DT->dominates(hoistBarrier, tarBB)))
            {
                hoistBarrier = tarBB;
                
            }
        }
        
        else if (LoopConsLevel == 0 && loop && tarLoop && !tarLoop->contains(loop))
        {
            tarBB = getValidBlockInLoopConstraint(loop, curBB, tarLoop);
            if (DT->dominates(tarBB, curBB) && (!hoistBarrier || DT->dominates(hoistBarrier, tarBB)))
            {
                hoistBarrier = tarBB;
                
            }
        }
    }

    BasicBlock *tarBB = nullptr;
    if (movePoint && (!hoistBarrier || DT->dominates(hoistBarrier, movePoint->getParent())))
    {
        if (auto invoke = dyn_cast<InvokeInst>(movePoint))
        {
            tarBB = invoke->getNormalDest();
        }
        else
        {
            tarBB = movePoint->getParent();
        }
    }
    else if (hoistBarrier)
    {
        tarBB = hoistBarrier;
    }
    if (tarBB && !DT->dominates(insn->getParent(), tarBB))
        insn->moveBefore(tarBB->getTerminator());
    return insn;
}

namespace
{
    class NestedIfNode;

    using BB2Cond = DenseMap<BasicBlock *, Value *>;
    using NestedIfNodeList = SmallVector<NestedIfNode *, 4>;

    static inline bool hasIntersect(const SmallVectorImpl<Value *> &vec,
                                    const SmallPtrSetImpl<Value *> &set)
    {
        for (auto &val : vec)
        {
            if (set.find(val) != set.end())
            {
                return true;
            }
        }
        return false;
    }

    class NestedIfNode
    {
        NestedIfNode *parent;
        NestedIfNode *root;
        /**
         * The calculation of predicate of current NI is dependent on the Ni.
         */
        NestedIfNode *hoistBorder;

        NestedIfNodeList ifThens;
        NestedIfNodeList ifElses;

        BasicBlock *bb;
        BasicBlock *entry;
        BranchInst *br;
        Instruction *cond;

        ConstantInt *brSrc;
        ConstantInt *thenEdge;
        ConstantInt *elseEdge;

        bool thenBranch;
        bool cmpSplit;

        SmallVector<Value *, 8> directDepVals;

        NestedIfNode(BasicBlock *bb, BranchInst *br, Instruction *cond);

        NestedIfNode(NestedIfNode *parent, NestedIfNode *root, BasicBlock *bb, BasicBlock *entry, BranchInst *br,
                     Instruction *cond,
                     bool isThen);

    public:
        static NestedIfNode *createRootNode(BasicBlock *root);

        bool empty()
        {
            return ifElses.empty() && ifThens.empty();
        }

        bool isRoot()
        {
            return parent == nullptr;
        }

        bool justOneChildBranch()
        {
            return ifElses.empty() ^ ifThens.empty();
        }

        void extractDirectDepVals();

        void extractHoistedInsnDepVals(SmallPtrSetImpl<Value *> &set);

        NestedIfNode *getParent() const
        {
            return parent;
        }

        void setParent(NestedIfNode *parent)
        {
            NestedIfNode::parent = parent;
        }

        bool isCompareSplit() const;

        ConstantInt *getBrSrc() const;

        ConstantInt *getThenEdge() const;

        ConstantInt *getElseEdge() const;

        NestedIfNode *getHoistBorder() const;

        void setHoistBorder(NestedIfNode *hoistBorder);

        NestedIfNode *getRoot() const;

        BasicBlock *getBB() const
        {
            return bb;
        }

        void setBb(BasicBlock *bb)
        {
            NestedIfNode::bb = bb;
        }

        Instruction *getCond() const
        {
            return cond;
        }

        void setCond(Instruction *cond)
        {
            NestedIfNode::cond = cond;
        }

        BasicBlock *getEntry() const
        {
            return entry;
        }

        void setEntry(BasicBlock *entry)
        {
            NestedIfNode::entry = entry;
        }

        const NestedIfNodeList &getIfThens() const
        {
            return ifThens;
        }

        const NestedIfNodeList &getIfElses() const
        {
            return ifElses;
        }

        bool isThen() const
        {
            return thenBranch;
        }

        BranchInst *getBranchInsn() const;

        const SmallVector<Value *, 8> &getDirectDepVals() const;

        void addToThen(NestedIfNode *parent)
        {
            parent->ifThens.push_back(this);
        }

        void addToElse(NestedIfNode *parent)
        {
            parent->ifElses.push_back(this);
        }

        NestedIfNode *addIfThen(BasicBlock *bb)
        {
            BranchInst *br;
            if (!(br = dyn_cast<BranchInst>(bb->getTerminator())))
            {
                return nullptr;
            }
            if (!br->isConditional())
            {
                return nullptr;
            }
            Instruction *cond = dyn_cast<Instruction>(br->getCondition());
            if (!cond)
                return nullptr;
            BasicBlock *entry = this->br->getSuccessor(0);
            NestedIfNode *ni = new NestedIfNode(this, this->root, bb, entry, br, cond, true);
            this->ifThens.push_back(ni);
            return ni;
        }

        NestedIfNode *addIfElse(BasicBlock *bb)
        {
            BranchInst *br;
            if (!(br = dyn_cast<BranchInst>(bb->getTerminator())))
            {
                return nullptr;
            }
            if (!br->isConditional())
            {
                return nullptr;
            }
            Instruction *cond = dyn_cast<Instruction>(br->getCondition());
            if (!cond)
                return nullptr;
            BasicBlock *entry = this->br->getSuccessor(1);
            NestedIfNode *ni = new NestedIfNode(this, this->root, bb, entry, br, cond, false);
            this->ifElses.push_back(ni);
            return ni;
        }

        NestedIfNode *getNestedIfHead();

        virtual ~NestedIfNode();
    };

    /**
     * 嵌套If 的表示形式
     *
     * 约束：
     *      1. 嵌套if不得跨越 loop
     *      2. 嵌套if不得跨越LoopExiting
     *      3. 嵌套if需标标记含强依赖关系的边
     */
    class NestedIf
    {
        NestedIfNode *root;

        void modifyCovInstArg(BasicBlock *curBB, Value *cond, bool isThen);

        void processCmpForTaintSink(CmpInst *Cmp, ConstantInt *thenEdge, ConstantInt *elseEdge,
                                    Instruction *InsertPoint1, Instruction *InsertPoint2);
        void processBoolCmpForTaintSink(Value *Cond, ConstantInt *thenEdge, ConstantInt *elseEdge,
                                        Instruction *InsertPoint, Instruction *InsertPoint2);

        void taintSinkForBranch(NestedIfNode *ni);

    public:
        NestedIf(NestedIfNode *root);

        virtual ~NestedIf();

        virtual void markHoistBarrier();

        void doMutateIf();

        void doRootHoist();

        void doSinkInstr();

        NestedIfNode *getRoot() const;
    };

}

void NestedIfNode::extractHoistedInsnDepVals(SmallPtrSetImpl<Value *> &set)
{
    if (isRoot())
        return;
    std::stack<Instruction *> st;
    st.push(cond);
    while (!st.empty())
    {

        Instruction *tmp = st.top();
        st.pop();
        if (!tmp)
            continue;

        BasicBlock *curBB = tmp->getParent();

        if (DT->dominates(curBB, parent->getBB()))
        {
            /**
             * 处理特殊的 Cast指令
             */
            addInsn2set(set, tmp)
        }
        if (isa<PHINode>(tmp))
            continue;

        /**
         * 写内存的一定不会 hoist, 所以可能hoist的只能是load指令和SSA IR，
         * 这里是避免hoist带来的语义变化，因为依赖于store指令的情况下本来就不hoist，所以即使不包含store指令来分析，也能保障最终结果的正确性
         * 所以不需要进行内存依赖分析
         */
        for (auto &op : tmp->operands())
        {
            /**
             * 要得到的应是入参，全卷变量抑或本BB外支配本BB的变量 （如此其外部if才能进行约束）
             */
            if (Instruction *opInsn = dyn_cast<Instruction>(op))
            {
                st.push(opInsn);
            }
            else if (
                isa<GlobalVariable>(op) ||
                isa<Argument>(op))
            {
                set.insert(op);
            }
        }
    }
}

void NestedIfNode::extractDirectDepVals()
{
    std::stack<Instruction *> st;
    st.push(cond);
    while (!st.empty())
    {

        Instruction *tmp = st.top();
        st.pop();
        if (!tmp)
            continue;
        BinaryOperator *bo;
        if (tmp->getType()->isIntegerTy(1) && (bo = dyn_cast<BinaryOperator>(tmp)))
        {
            st.push(dyn_cast<Instruction>(bo->getOperand(0)));
            st.push(dyn_cast<Instruction>(bo->getOperand(1)));
        }
        else
        {
            for (auto &op : tmp->operands())
            {
                /**
                 * 处理特殊的 Cast指令
                 */
                if (isa<Instruction>(op))
                {
                    if (op->getType()->isIntegerTy(1))
                        continue;
                    addInsn2vec(directDepVals, op)
                }
                else if (
                    isa<GlobalVariable>(op) ||
                    isa<Argument>(op))
                {
                    directDepVals.push_back(op);
                }
            }
        }
    }
}

BranchInst *NestedIfNode::getBranchInsn() const
{
    return br;
}

const SmallVector<Value *, 8> &NestedIfNode::getDirectDepVals() const
{
    return directDepVals;
}

NestedIfNode *NestedIfNode::getNestedIfHead()
{
    return hoistBorder == nullptr ? root : hoistBorder;
}

[[maybe_unused]]
static bool isDirectlyAffectedByPHI(BasicBlock *from, BasicBlock *to)
{
    for (auto &phi : to->phis())
    {
        int idx = phi.getBasicBlockIndex(from);
        if (idx != -1)
        {
            return true;
        }
    }
    return false;
}

NestedIfNode::NestedIfNode(NestedIfNode *parent, NestedIfNode *root, BasicBlock *bb, BasicBlock *entry, BranchInst *br,
                           Instruction *cond, bool isThen) : parent(parent), root(root), hoistBorder(nullptr), bb(bb),
                                                             entry(entry),
                                                             br(br),
                                                             cond(cond),
                                                             thenBranch(isThen)
{

    u32 then_id = next_edge_id();
    u32 else_id = next_edge_id();

    thenEdge = num2LLVMConstant(then_id);
    elseEdge = num2LLVMConstant(else_id);
    cmpSplit = isCmpSplit(bb);
}

NestedIfNode::NestedIfNode(BasicBlock *bb, BranchInst *br, Instruction *cond)
    : parent(nullptr), root(this), hoistBorder(nullptr), bb(bb), entry(bb), br(br), cond(cond)
{

    u32 then_id = next_edge_id();
    u32 else_id = next_edge_id();

    thenEdge = num2LLVMConstant(then_id);
    elseEdge = num2LLVMConstant(else_id);
    cmpSplit = isCmpSplit(bb);
}

NestedIfNode::~NestedIfNode()
{
    for (auto ifThen : ifThens)
    {
        delete ifThen;
    }
    ifThens.clear();
    for (auto ifElse : ifElses)
    {
        delete ifElse;
    }
    ifElses.clear();
}

bool NestedIfNode::isCompareSplit() const
{
    return cmpSplit;
}

NestedIfNode *NestedIfNode::getHoistBorder() const
{
    return hoistBorder;
}

void NestedIfNode::setHoistBorder(NestedIfNode *hoistBorder)
{
    NestedIfNode::hoistBorder = hoistBorder;
}

NestedIfNode *NestedIfNode::createRootNode(BasicBlock *root)
{
    BranchInst *term = dyn_cast<BranchInst>(root->getTerminator());
    if ((!term) || !term->isConditional())
        return nullptr;
    Instruction *cond = dyn_cast<Instruction>(term->getCondition());
    if (!cond)
        return nullptr;

    return new NestedIfNode(root, term, cond);
}

ConstantInt *NestedIfNode::getBrSrc() const
{
    return brSrc;
}

ConstantInt *NestedIfNode::getThenEdge() const
{
    return thenEdge;
}

ConstantInt *NestedIfNode::getElseEdge() const
{
    return elseEdge;
}

NestedIfNode *NestedIfNode::getRoot() const
{
    return root;
}

void NestedIf::modifyCovInstArg(BasicBlock *curBB, Value *cond, bool isThen)
{
    
    if (CallInst *instFuncCall = dyn_cast<CallInst>(curBB->getFirstNonPHIOrDbgOrLifetime()))
    {
        Instruction *thenTerm, *elseTerm;
        SplitBlockAndInsertIfThenElse(cond, instFuncCall, &thenTerm, &elseTerm);
        if (isThen)
        {
            instFuncCall->moveBefore(thenTerm);
            CallInst *anotherCall = dyn_cast<CallInst>(instFuncCall->clone());
            if (ConstantInt *arg = dyn_cast<ConstantInt>(instFuncCall->getArgOperand(0)))
            {
                int num = arg->getSExtValue();
                auto *minusNum = ConstantInt::get(arg->getType(), -num, true);
                anotherCall->setArgOperand(0, minusNum);
                anotherCall->insertBefore(elseTerm);
            }
        }
        else
        {
            instFuncCall->moveBefore(elseTerm);
            CallInst *anotherCall = dyn_cast<CallInst>(instFuncCall->clone());
            if (ConstantInt *arg = dyn_cast<ConstantInt>(instFuncCall->getArgOperand(0)))
            {
                int num = arg->getSExtValue();
                auto *minusNum = ConstantInt::get(arg->getType(), -num, true);
                anotherCall->setArgOperand(0, minusNum);
                anotherCall->insertBefore(thenTerm);
            }
        }
    }
}

void NestedIf::markHoistBarrier()
{
    if (SourceMode || LafMode)
        return;
    SmallPtrSet<Value *, 16> hoistedInsnDepVals;
    std::stack<NestedIfNode *> st;
    st.push(root);

    
    while (!st.empty())
    {
        NestedIfNode *ni = st.top();
        st.pop();

        ni->extractDirectDepVals();

        for (NestedIfNode *ifElse : ni->getIfElses())
        {
            st.push(ifElse);
        }

        for (NestedIfNode *ifThen : ni->getIfThens())
        {
            st.push(ifThen);
        }

        if (ni->isRoot())
            continue;

        
        
        
        
        
        
        
        
        
        
        
        
        

        ni->extractHoistedInsnDepVals(hoistedInsnDepVals);

        
        
        
        
        
        
        
        
        
        
        
        

        NestedIfNode *parent = ni->getParent(), *cur = ni;
        
        if (ni->isCompareSplit())
        {
            while (parent != nullptr)
            {
                if (!parent->isCompareSplit())
                    break;
                if (isHoistBarrierBB(parent->getBB()))
                {
                    ni->setHoistBorder(cur);
                    break;
                }
                cur = parent;
                parent = parent->getParent();
            }
        }

        while (parent != nullptr)
        {

            if (hasIntersect(parent->getDirectDepVals(), hoistedInsnDepVals))
            {
                ni->setHoistBorder(cur);
                
                
                
                
                
                
                
                
                break;
            }
            cur = parent;
            parent = parent->getParent();
        }
        if (!ni->getHoistBorder())
        {
            ni->setHoistBorder(ni->getRoot());
        }

        hoistedInsnDepVals.clear();
    }
}

void NestedIf::doMutateIf()
{
    if (!root->empty())
    {
        markHoistBarrier();
        doRootHoist();
    }
    doSinkInstr();
}

void NestedIf::doRootHoist()
{
    if (SourceMode || LafMode)
        return;
    std::stack<NestedIfNode *> st;
    st.push(root);
    while (!st.empty())
    {
        NestedIfNode *ni = st.top();
        st.pop();
        for (NestedIfNode *ifElse : ni->getIfElses())
        {
            st.push(ifElse);
        }

        for (NestedIfNode *ifThen : ni->getIfThens())
        {
            st.push(ifThen);
        }

        NestedIfNode *head = ni->getNestedIfHead();

        if (head && head != ni)
        {
            insnHoist(ni->getCond(), head->getBB());
        }
    }
}

void NestedIf::doSinkInstr()
{
    std::stack<NestedIfNode *> st;
    st.push(root);

    while (!st.empty())
    {
        NestedIfNode *ni = st.top();
        st.pop();

        Instruction *cond = ni->getCond();
        for (NestedIfNode *ifElse : ni->getIfElses())
        {
            st.push(ifElse);
        }

        for (NestedIfNode *ifThen : ni->getIfThens())
        {
            st.push(ifThen);
        }

        ConstantInt *thenEdge = ni->getThenEdge(),
                    *elseEdge = ni->getElseEdge();

        if (PhantomMode || IntegMode)
        {
            
            
            
            
            
            
            
            
            
            
            
            

            Instruction *insertPoint = cond->getNextNonDebugInstruction();
            
            if (!insertPoint)
            {
                
                if (auto invoke = dyn_cast<InvokeInst>(cond))
                {
                    BasicBlock *normalDest = invoke->getNormalDest();
                    insertPoint = normalDest->getFirstNonPHIOrDbgOrLifetime();
                }
            }

            if (insertPoint)
            {
                if (isa<PHINode>(insertPoint))
                {
                    insertPoint = insertPoint->getParent()->getFirstNonPHIOrDbgOrLifetime();
                }
                while (isa<LandingPadInst>(insertPoint) || isa<ExtractValueInst>(insertPoint))
                {
                    insertPoint = insertPoint->getNextNonDebugInstruction();
                }
                CallInst::Create(phantomFunc, {cond, thenEdge, elseEdge}, "",
                                 insertPoint);
            }
        }

        if (SourceMode || IntegMode)
            CallInst::Create(sourceSinkFunc, {cond, thenEdge, elseEdge},
                             "",
                             ni->getBranchInsn());
        if (PinMode || IntegMode)
            taintSinkForBranch(ni);
    }
}

NestedIf::NestedIf(NestedIfNode *root) : root(root)
{
}

NestedIf::~NestedIf()
{
    delete root;
}

NestedIfNode *NestedIf::getRoot() const
{
    return root;
}

void NestedIf::taintSinkForBranch(NestedIfNode *ni)
{
    BranchInst *Br = ni->getBranchInsn();
    if (Br->isConditional() && Br->getNumSuccessors() == 2)
    {

        Instruction *Cond = ni->getCond();
        if (Cond && Cond->getType()->isIntegerTy())
        {
            if (auto Cmp = dyn_cast<CmpInst>(Cond))
            {
                Instruction *InsertPoint = Cmp->getNextNode();
                if (!InsertPoint)
                    InsertPoint = Br;
                processCmpForTaintSink(Cmp, ni->getThenEdge(), ni->getElseEdge(), InsertPoint, Br);
            }
            else
            {
                BasicBlock *tarBB = nullptr;
                if (auto invoke = dyn_cast<InvokeInst>(Cond))
                {
                    tarBB = invoke->getNormalDest();
                }
                else
                {
                    tarBB = Cond->getParent();
                }

                Instruction *InsertPoint = tarBB ? tarBB->getTerminator() : nullptr;
                if (!InsertPoint)
                {
                    InsertPoint = Br;
                }
                
                processBoolCmpForTaintSink(Cond, ni->getThenEdge(), ni->getElseEdge(), InsertPoint, Br);
            }
        }
    }
}

void NestedIf::processCmpForTaintSink(CmpInst *Cmp, ConstantInt *thenEdge, ConstantInt *elseEdge,
                                      Instruction *InsertPoint1, Instruction *InsertPoint2)
{
    Value *OpArg[2];
    OpArg[0] = Cmp->getOperand(0);
    OpArg[1] = Cmp->getOperand(1);
    Type *OpType = OpArg[0]->getType();
    if (!((OpType->isIntegerTy() && OpType->getIntegerBitWidth() <= 64) ||
          OpType->isFloatTy() || OpType->isDoubleTy() || OpType->isPointerTy()))
    {
        processBoolCmpForTaintSink(Cmp, thenEdge, elseEdge, InsertPoint1, InsertPoint2);
        return;
    }
    int num_bytes = OpType->getScalarSizeInBits() / 8;
    if (num_bytes == 0)
    {
        if (OpType->isPointerTy())
        {
            num_bytes = 8;
        }
        else
        {
            return;
        }
    }
    IRBuilder<> IRB(InsertPoint1);

    Value *SizeArg = ConstantInt::get(Int32Ty, num_bytes);
    Value *CondExt = IRB.CreateZExt(Cmp, Int32Ty);
    SetNoSanitize(CondExt);
    OpArg[0] = castArgType(IRB, OpArg[0]);
    OpArg[1] = castArgType(IRB, OpArg[1]);

    CallInst *ProxyCall =
        IRB.CreateCall(phantomDTASink, {thenEdge, elseEdge, CondExt, SizeArg, OpArg[0], OpArg[1]});
    SetNoSanitize(ProxyCall);

    IRB.SetInsertPoint(InsertPoint2);
    ProxyCall =
        IRB.CreateCall(sourceDTASink, {thenEdge, elseEdge, CondExt, SizeArg, OpArg[0], OpArg[1]});
    SetNoSanitize(ProxyCall);
}

void NestedIf::processBoolCmpForTaintSink(Value *Cond, ConstantInt *thenEdge, ConstantInt *elseEdge,
                                          Instruction *InsertPoint1, Instruction *InsertPoint2)
{
    if (!Cond->getType()->isIntegerTy() ||
        Cond->getType()->getIntegerBitWidth() > 32)
        return;
    Value *OpArg[2];
    OpArg[1] = ConstantInt::get(Int64Ty, 1);
    IRBuilder<> IRB(InsertPoint1);

    Value *SizeArg = ConstantInt::get(Int32Ty, 1);
    Value *CondExt = IRB.CreateZExt(Cond, Int32Ty);
    SetNoSanitize(CondExt);
    OpArg[0] = IRB.CreateZExt(CondExt, Int64Ty);
    SetNoSanitize(OpArg[0]);

    CallInst *ProxyCall =
        IRB.CreateCall(phantomDTASink, {thenEdge, elseEdge, CondExt, SizeArg, OpArg[0], OpArg[1]});
    SetNoSanitize(ProxyCall);

    IRB.SetInsertPoint(InsertPoint2);
    ProxyCall =
        IRB.CreateCall(sourceDTASink, {thenEdge, elseEdge, CondExt, SizeArg, OpArg[0], OpArg[1]});
    SetNoSanitize(ProxyCall);
}

static u32 extractNestedIfs(SmallVectorImpl<NestedIf *> &vec)
{
    DenseMap<BasicBlock *, NestedIfNode *> bb2node;

    std::stack<BasicBlock *> bbs;

    for (auto node : post_order(DT->getRootNode()))
    {
        BasicBlock *BB = node->getBlock();
        if (isSanitizeBB(BB))
            continue;
        bbs.push(BB);
    }
    while (!bbs.empty())
    {
        BasicBlock *BB = bbs.top(), *scopeHeader = entryBB;
        bbs.pop();

        Instruction *inst = (BB)->getTerminator();

        BranchInst *br;
        if ((br = dyn_cast<BranchInst>(inst)) && (br->isConditional()))
        {
            if (br->getNumSuccessors() != 2)
                continue;
            Instruction *cond = dyn_cast<Instruction>(br->getCondition());
            if (!cond)
                continue;
            
            
            
            
            
            
            
            
            
            BasicBlock *parentBB = getOuterBlock(BB, scopeHeader);
            NestedIfNode *parentNode = bb2node[parentBB];
            NestedIfNode *node;
            if (parentNode)
            {
                if (isTrueSuccessor(parentNode->getBranchInsn(), BB))
                {
                    node = parentNode->addIfThen(BB);
                }
                else
                {
                    node = parentNode->addIfElse(BB);
                }
                if (!node)
                    continue;
                bb2node[BB] = node;
            }
            else
            {
                node = NestedIfNode::createRootNode(BB);
                if (!node)
                    continue;
                bb2node[BB] = node;
                vec.push_back(/*isBBOwnMetadata(BB, CMP_SPLIT) ?
                              new CmpSplitNestedIf(node) : */
                              new NestedIf(node));
            }
        }
    }
    return vec.size();
}

namespace
{

    using SmallSet32 = SmallSet<Value *, 32>;

    struct IntegratedCovPhantom : public ModulePass
    {
        static char ID;
        std::string moduleName;
        u32 numBB;

        IntegratedCovPhantom() : ModulePass(ID), numBB(0)
        {
            initializePromoteLegacyPassPass(*PassRegistry::getPassRegistry());
        }

        inline u32 getIDOfBB(BasicBlock *bb)
        {
            if (bb == nullptr)
                return 0;
            for (auto &insn : bb->getInstList())
            {
                if (CallInst *call = dyn_cast<CallInst>(&insn))
                {
                    if (call->getCalledFunction()->getName() == COV_FUNC)
                    {
                        if (ConstantInt *arg = dyn_cast<ConstantInt>(call->getArgOperand(0)))
                        {
                            return arg->getZExtValue();
                        }
                    }
                }
            }
            return 0;
        }

        bool doInitialization(Module &module) override;

        bool doFinalization(Module &module) override;

        bool runOnModule(Module &M) override;

        void preModulePass(Module &M);

        void preMutateIf(Function &F);

        virtual bool transformOnFunc(Function &F);

        bool isAFLInstrumentFunc(Function *F)
        {
            return F->getName() == "__Instrument__";
        }

        bool isAFLInstrumentedBB(BasicBlock *bb)
        {
            Instruction *inst = bb->getFirstNonPHIOrDbgOrLifetime();

            if (CallInst *call = dyn_cast<CallInst>(inst))
            {
                return isAFLInstrumentFunc(call->getCalledFunction());
            }
            return false;
        }

        void getAnalysisUsage(AnalysisUsage &AU) const override;

        void postMutateIf(Function &F);

        void handleExitDel(CallInst *exitCall, BasicBlock::iterator &DI);
    };
}

char IntegratedCovPhantom::ID = 0;


void IntegratedCovPhantom::getAnalysisUsage(AnalysisUsage &AU) const
{
    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addRequired<PostDominatorTreeWrapperPass>();
    AU.addRequired<LoopInfoWrapperPass>();
    AU.addRequired<AAResultsWrapperPass>();
}

static void prepare(Module &M)
{
    LLVMContext &C = M.getContext();

    VOID = Type::getVoidTy(C);
    Int1Ty = IntegerType::getInt1Ty(C);
    Int8Ty = IntegerType::getInt8Ty(C);
    Int16Ty = IntegerType::getInt16Ty(C);
    Int32Ty = IntegerType::getInt32Ty(C);
    Int64Ty = IntegerType::getInt64Ty(C);

    NEG_ONE_32 = ConstantInt::get(Int32Ty, -1, true);
    SEVEN_32 = ConstantInt::get(Int32Ty, 7);
    THREE_32 = ConstantInt::get(Int32Ty, 3);
    ONE_32 = ConstantInt::get(Int32Ty, 1);
    U255_8 = ConstantInt::get(Int8Ty, 255);
    ONE_8 = ConstantInt::get(Int8Ty, 1);
    TWO_8 = ConstantInt::get(Int8Ty, 2);
    FULL_ONE_8 = ConstantInt::get(Int8Ty, 255);

    /* Get globals for the SHM region and the previous location. Note that
       __afl_prev_loc is thread-local. */

    
    

    StoreInst *Store;
    LoadInst *Load;
    Function *newFun;
    FunctionType *funcType;
    BasicBlock *entry;
    ReturnInst *ret;
    LoadInst *MapPtr;

    IRBuilder<> IRB(M.getContext());

    if (!PinMode)
    {
        GlobalVariable *AFLMapPtr =
            new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                               GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

        GlobalVariable *AFLPrevLoc = new GlobalVariable(
            M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
            0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

        std::vector<Type *> argsType({Int32Ty});
        funcType = FunctionType::get(VOID, argsType, false);

        newFun = Function::Create(funcType, GlobalValue::InternalLinkage, COV_FUNC, M);

        entry = BasicBlock::Create(newFun->getContext(), "entry", newFun);
        IRB.SetInsertPoint(entry);
        Argument *arg = newFun->getArg(0);

        LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
        SetNoSanitize(PrevLoc);

        Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

        /* Load SHM pointer */

        MapPtr = IRB.CreateLoad(AFLMapPtr);
        SetNoSanitize(MapPtr);
        Value *MapPtrIdx =
            IRB.CreateGEP(MapPtr, IRB.CreateZExt(IRB.CreateXor(PrevLocCasted, arg), Int64Ty));

        /* Update bitmap */

        LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
        SetNoSanitize(Counter);
        Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
        Store = IRB.CreateStore(Incr, MapPtrIdx);
        SetNoSanitize(Store);
        Value *val = IRB.CreateLShr(arg, ConstantInt::get(arg->getType(), 1));
        /* Set prev_loc to cur_loc >> 1 */
        Store = IRB.CreateStore(val, AFLPrevLoc);
        SetNoSanitize(Store);

        ret = IRB.CreateRet(nullptr);

        SetFuncMetadata(newFun, INSTRUMENT);
        covFunc = newFun;
    }

    if (LafMode)
        return;

    Instruction *thenTerm, *elseTerm, *term;
    Value *Seg, *Bit, *SegEntry, *SegEntryPtr, *NotNegOne;

    if (PhantomMode || IntegMode)
    {

        GlobalVariable *PhantomBitmap =
            new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                               GlobalValue::ExternalLinkage, 0, "__phantom_bitmap_ptr");
        GlobalVariable *CrashMask =
            new GlobalVariable(M, Int8Ty, false,
                               GlobalValue::ExternalLinkage, 0, "__crash_mask",
                               0, GlobalVariable::GeneralDynamicTLSModel, 0, true);

        funcType = FunctionType::get(VOID, {Int1Ty, Int32Ty, Int32Ty}, false);
        newFun = Function::Create(funcType, GlobalValue::InternalLinkage, PHANTOM_FUNC, M);
        entry = BasicBlock::Create(newFun->getContext(), "entry", newFun);
        IRB.SetInsertPoint(entry);

        Argument *cond = newFun->getArg(0),
                 *thenEdge = newFun->getArg(1),
                 *elseEdge = newFun->getArg(2);

        Store = IRB.CreateStore(FULL_ONE_8, CrashMask);
        SetNoSanitize(Store);
        ret = IRB.CreateRet(nullptr);

        SplitBlockAndInsertIfThenElse(cond, Store, &thenTerm, &elseTerm);
        {
            IRB.SetInsertPoint(thenTerm);
            NotNegOne = IRB.CreateICmpNE(thenEdge, NEG_ONE_32);
            term = SplitBlockAndInsertIfThen(NotNegOne, thenTerm, false);
            {
                IRB.SetInsertPoint(term);

                Seg = IRB.CreateZExt(IRB.CreateLShr(thenEdge, THREE_32, "seg"), Int64Ty);
                Bit = IRB.CreateTrunc(IRB.CreateShl(ONE_32, IRB.CreateAnd(thenEdge, SEVEN_32), "bit"), Int8Ty);
                Load = IRB.CreateLoad(CrashMask);
                SetNoSanitize(Load);
                Bit = IRB.CreateAnd(Bit, Load);

                MapPtr = IRB.CreateLoad(PhantomBitmap);
                SetNoSanitize(MapPtr);
                SegEntryPtr = IRB.CreateGEP(MapPtr, Seg);
                SegEntry = IRB.CreateLoad(SegEntryPtr);
                SetNoSanitize(SegEntry);

                Store = IRB.CreateStore(IRB.CreateOr(SegEntry, Bit), SegEntryPtr);
                SetNoSanitize(Store);
            }
        }
        {
            IRB.SetInsertPoint(elseTerm);
            NotNegOne = IRB.CreateICmpNE(elseEdge, NEG_ONE_32);
            term = SplitBlockAndInsertIfThen(NotNegOne, elseTerm, false);
            {
                IRB.SetInsertPoint(term);

                Seg = IRB.CreateZExt(IRB.CreateLShr(elseEdge, THREE_32, "seg"), Int64Ty);
                Bit = IRB.CreateTrunc(IRB.CreateShl(ONE_32, IRB.CreateAnd(elseEdge, SEVEN_32), "bit"), Int8Ty);
                Load = IRB.CreateLoad(CrashMask);
                SetNoSanitize(Load);
                Bit = IRB.CreateAnd(Bit, Load);

                MapPtr = IRB.CreateLoad(PhantomBitmap);
                SetNoSanitize(MapPtr);
                SegEntryPtr = IRB.CreateGEP(MapPtr, Seg);
                SegEntry = IRB.CreateLoad(SegEntryPtr);
                SetNoSanitize(SegEntry);

                Store = IRB.CreateStore(IRB.CreateOr(SegEntry, Bit), SegEntryPtr);
                SetNoSanitize(Store);
            }
        }

        SetFuncMetadata(newFun, INSTRUMENT);
        phantomFunc = newFun;
    }

    
    if (SourceMode || IntegMode)
    {
        GlobalVariable *SourceMapPtr =
            new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                               GlobalValue::ExternalLinkage, 0, "__source_map_ptr");

        funcType = FunctionType::get(Type::getVoidTy(C), {Int1Ty, Int32Ty, Int32Ty}, false);
        newFun = Function::Create(funcType, GlobalValue::InternalLinkage, SOURCE_FUNC, M);
        Argument *cond = newFun->getArg(0),
                 *thenEdge = newFun->getArg(1),
                 *elseEdge = newFun->getArg(2);

        entry = BasicBlock::Create(newFun->getContext(), "entry", newFun);
        IRB.SetInsertPoint(entry);

        ret = IRB.CreateRet(nullptr);

        Value *SourceEntry, *SourceEntryPtr;

        SplitBlockAndInsertIfThenElse(cond, ret, &thenTerm, &elseTerm);

        {
            IRB.SetInsertPoint(thenTerm);
            {
                NotNegOne = IRB.CreateICmpNE(thenEdge, NEG_ONE_32);
                term = SplitBlockAndInsertIfThen(NotNegOne, thenTerm, false);
                IRB.SetInsertPoint(term);

                MapPtr = IRB.CreateLoad(SourceMapPtr);
                SetNoSanitize(MapPtr);

                SourceEntryPtr = IRB.CreateGEP(MapPtr, IRB.CreateZExt(thenEdge, Int64Ty));
                Store = IRB.CreateStore(U255_8, SourceEntryPtr);
                SetNoSanitize(Store);
            }
            IRB.SetInsertPoint(thenTerm);
            {
                NotNegOne = IRB.CreateICmpNE(elseEdge, NEG_ONE_32);
                term = SplitBlockAndInsertIfThen(NotNegOne, thenTerm, false);
                IRB.SetInsertPoint(term);

                MapPtr = IRB.CreateLoad(SourceMapPtr);
                SetNoSanitize(MapPtr);
                SourceEntryPtr = IRB.CreateGEP(MapPtr, IRB.CreateZExt(elseEdge, Int64Ty));
                SourceEntry = IRB.CreateLoad(SourceEntryPtr);
                SetNoSanitize(SourceEntry);
                Store = IRB.CreateStore(IRB.CreateOr(SourceEntry, ONE_8), SourceEntryPtr);
                SetNoSanitize(Store);
            }
        }

        {
            IRB.SetInsertPoint(elseTerm);
            {
                NotNegOne = IRB.CreateICmpNE(elseEdge, NEG_ONE_32);
                term = SplitBlockAndInsertIfThen(NotNegOne, elseTerm, false);
                IRB.SetInsertPoint(term);

                MapPtr = IRB.CreateLoad(SourceMapPtr);
                SetNoSanitize(MapPtr);
                SourceEntryPtr = IRB.CreateGEP(MapPtr, IRB.CreateZExt(elseEdge, Int64Ty));
                Store = IRB.CreateStore(U255_8, SourceEntryPtr);
                SetNoSanitize(Store);
            }
            IRB.SetInsertPoint(elseTerm);
            {
                NotNegOne = IRB.CreateICmpNE(thenEdge, NEG_ONE_32);
                term = SplitBlockAndInsertIfThen(NotNegOne, elseTerm, false);
                IRB.SetInsertPoint(term);

                MapPtr = IRB.CreateLoad(SourceMapPtr);
                SetNoSanitize(MapPtr);
                SourceEntryPtr = IRB.CreateGEP(MapPtr, IRB.CreateZExt(thenEdge, Int64Ty));
                SourceEntry = IRB.CreateLoad(SourceEntryPtr);
                SetNoSanitize(SourceEntry);
                Store = IRB.CreateStore(IRB.CreateOr(SourceEntry, TWO_8), SourceEntryPtr);
                SetNoSanitize(Store);
            }
        }

        SetFuncMetadata(newFun, INSTRUMENT);
        sourceSinkFunc = newFun;
    }

    if (PinMode || IntegMode)
    {
        funcType = FunctionType::get(VOID, {Int32Ty, Int32Ty, Int32Ty, Int32Ty, Int64Ty, Int64Ty}, false);
        AttributeList AL;
        AL = AL.addAttribute(C, AttributeList::FunctionIndex, Attribute::NoUnwind);
        sourceDTASink = M.getOrInsertFunction(SOURCE_TAINT_FUNC, funcType, AL);
        phantomDTASink = M.getOrInsertFunction(PHANTOM_TAINT_FUNC, funcType, AL);
    }
}

bool IntegratedCovPhantom::doInitialization(Module &module)
{
    moduleName = getUniqModuleName(module);
    uid_t uid = getuid();
    struct passwd *pw = getpwuid(uid);
    std::string edgeIdFilePath = pw->pw_dir;
    edgeIdFilePath += "/.miragefuzz/";
    if (PhantomMode)
    {
        edgeIdFilePath += "phantom";
    }
    else if (SourceMode)
    {
        edgeIdFilePath += "source";
    }
    else if (PinMode)
    {
        edgeIdFilePath += "pin";
    }
    else {
        return Pass::doInitialization(module) ;
    }
    FILE *f = fopen(edgeIdFilePath.c_str(), "rb");
    if (f)
    {
        fread(&edge_id, sizeof(u32), 1, f);
        fclose(f);
    }
    else
    {
        edge_id = 1;
    }

    return Pass::doInitialization(module);
}

bool IntegratedCovPhantom::doFinalization(Module &module)
{
    uid_t uid = getuid();
    struct passwd *pw = getpwuid(uid);
    std::string edgeIdFilePath = pw->pw_dir;
    edgeIdFilePath += "/.miragefuzz/";
    if (access(edgeIdFilePath.c_str(), 0) == -1)
    {
        mkdir(edgeIdFilePath.c_str(), 0700);
    }
    if (PhantomMode)
    {
        edgeIdFilePath += "phantom";
    }
    else if (SourceMode)
    {
        edgeIdFilePath += "source";
    }
    else if (PinMode)
    {
        edgeIdFilePath += "pin";
    } else {
        return Pass::doFinalization(module);;
    }
    FILE *f = fopen(edgeIdFilePath.c_str(), "w");
    if (f)
    {
        fwrite(&edge_id, sizeof(u32), 1, f);
        fclose(f);
    }
    outs() << "------------------\n"
           << "BB Size: " << numBB
           << "\tEdge Size: " << edge_num
           << "\tThe final: " << edge_id 
           << "\n---------------------\n";

    return Pass::doFinalization(module);
}

bool IntegratedCovPhantom::runOnModule(Module &M)
{
    /* Show a banner */
    if (isatty(2) && !getenv("MIRAGEFUZZ_QUIET"))
    {
        if (IntegMode)
        {
            SAYF(cCYA
                 "integ-phantom-llvm-pass " cBRI
                 "do all in one target!!!\n" cRST);
        }
        else if (PhantomMode)
        {
            SAYF(cCYA
                 "phantom-llvm-pass " cBRI
                 "planarize nested if structure and record the phantom edge\n" cRST);
        }
        else if (SourceMode)
        {
            SAYF(cCYA
                 "source-llvm-pass " cBRI
                 "record the source unexplore edges\n" cRST);
        }
        else if (PinMode)
        {
            SAYF(cCYA
                 "pin-track-llvm-pass " cBRI
                 "provide taint sink hook for PIN DTA\n" cRST);
        }
        else if (LafMode)
        {
            SAYF(cCYA
                 "laf-like-llvm-pass " cBRI
                 "equivalent to AFL-laf, but simplify the compare split\n" cRST);
        }
        else if (AFLMode)
        {
            SAYF(cCYA
                 "afl-like-llvm-pass " cBRI
                 "equivalent to AFL llvm mode\n" cRST);
        }

        if(NoLaf) {
            SAYF(cCYA
                 "disable laf\n"  cRST);
        }
    }


    preModulePass(M);

    prepare(M);

    for (auto &F : M)
    {
        if (isFuncShouldSkip(&F))
            continue;

        preMutateIf(F);
        transformOnFunc(F);
        postMutateIf(F);
    }

#ifdef DEBUG
    std::string out_f = M.getName();
    if (IntegMode)
    {
        out_f += ".integ.ll";
    }
    else if (PhantomMode)
    {
        out_f += ".phantom.ll";
    }
    else if (SourceMode)
    {
        out_f += ".source.ll";
    }
    else if (PinMode)
    {
        out_f += ".pin.ll";
    }
    else
    {
        out_f += ".laf.ll";
    }
    int fd = open(out_f.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    dup2(fd, 2);
    M.print(errs(), nullptr);
    close(fd);
#endif

    return true;
}

bool IntegratedCovPhantom::transformOnFunc(Function &F)
{
    if (isFuncShouldSkip(&F))
        return false;
    if (isSanitizeFunc(&F))
        return false;

    for (auto &BB : F)
    {
        numBB++;
        if (isSanitizeBB(&BB))
            continue;

        u32 cur_loc = TS_R(MAP_SIZE);

        if (PinMode)
            continue;

        ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

        BasicBlock::iterator IP = BB.getFirstInsertionPt();
        IRBuilder<> IRB(&(*IP));
        CallInst *call = IRB.CreateCall(covFunc, {CurLoc});
        SetMetadata(call, "mirage_fuzz");
    }

    if (LafMode || AFLMode)
    {
        return true;
    }

    SmallVector<NestedIf *, 16> nestedIfs;
    extractNestedIfs(nestedIfs);
    for (auto nestedIf : nestedIfs)
    {
        nestedIf->doMutateIf();
        delete nestedIf;
    }

    if (llvm::verifyFunction(F, &llvm::errs()))
    {
        int fd = open("error.ll", O_WRONLY | O_CREAT, 0600);
        dup2(fd, 2);
        F.print(errs());
        close(fd);
        llvm::report_fatal_error("Bad function");
    }

    return true;
}


void IntegratedCovPhantom::postMutateIf(Function &F)
{
}

void IntegratedCovPhantom::preMutateIf(Function &F)
{
    
    if (F.isDeclaration())
        return;
    if (LafMode)
        return;
    entryBB = &F.getEntryBlock();
    DT = &getAnalysis<DominatorTreeWrapperPass>(F).getDomTree();
    PDT = &getAnalysis<PostDominatorTreeWrapperPass>(F).getPostDomTree();
    
    LI = &getAnalysis<LoopInfoWrapperPass>(F).getLoopInfo();
    auto AA = &getAnalysis<AAResultsWrapperPass>(F).getAAResults();
    MSSA = new MemorySSA(F, AA, DT);
    
    
}

void IntegratedCovPhantom::preModulePass(Module &M)
{
    if(AFLMode) return;
    commonModuleTransform(M, NoLaf);
}



static void registerPass(const PassManagerBuilder &,
                         legacy::PassManagerBase &PM)
{
    PM.add(new IntegratedCovPhantom());
}

/**
 * Register the llvm Pass, such that we can use `opt -<pass_name>` to trigger this pass
 */
static RegisterPass<IntegratedCovPhantom> X("i-phantom", "Integrated Mutate Nested If Structure",
                                          false, false);

/* Specify the extension point, such that we can load the pass by clang in the whole compilation pipeline. */
static RegisterStandardPasses RegisterMutIfPass(
    PassManagerBuilder::EP_ModuleOptimizerEarly, registerPass);


static RegisterStandardPasses RegisterMutIfPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerPass);

