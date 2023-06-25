#include "NestedIf.hpp"
#include "utils.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/MemorySSA.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <stack>
#include <llvm/IR/Instruction.h>
#include <vector>




namespace llvm {

static DominatorTree *DT;
static PostDominatorTree *PDT;
static LoopInfo *LI;
static MemorySSA *MSSA;

static bool HoistCallInst = false;
static uint8_t LoopConsLevel = 1;

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


static inline u32 next_edge_id()
{
    static u32 edge_id = 1;
    if (++edge_id == 0x10000) {
        edge_id = 1;
    }
    return edge_id;
}


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

static inline bool isThenSuccessor(const BranchInst *branchInst,
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
        NV = IRB.CreateFPToUI(V, IRB.getInt32Ty());
        SetNoSanitize(NV);
        NV = IRB.CreateIntCast(NV, IRB.getInt64Ty(), false);
        SetNoSanitize(NV);
    }
    else if (OpType->isDoubleTy())
    {
        NV = IRB.CreateFPToUI(V, IRB.getInt64Ty());
        SetNoSanitize(NV);
    }
    else if (OpType->isPointerTy())
    {
        NV = IRB.CreatePtrToInt(V, IRB.getInt64Ty());
    }
    else
    {
        if (OpType->isIntegerTy() && OpType->getIntegerBitWidth() < 64)
        {
            NV = IRB.CreateZExt(V, IRB.getInt64Ty());
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


void NestedIfNode::extractHoistedInsnDepVals(SmallPtrSetImpl<Value *> &set) {
  if (isRoot())
    return;
  std::stack<Instruction *> st;
  st.push(cond);
  while (!st.empty()) {

    Instruction *tmp = st.top();
    st.pop();
    if (!tmp)
      continue;

    BasicBlock *curBB = tmp->getParent();

    if (DT->dominates(curBB, parent->getBB())) {
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
    for (auto &op : tmp->operands()) {
      /**
       * 要得到的应是入参，全卷变量抑或本BB外支配本BB的变量
       * （如此其外部if才能进行约束）
       */
      if (Instruction *opInsn = dyn_cast<Instruction>(op)) {
        st.push(opInsn);
      } else if (isa<GlobalVariable>(op) || isa<Argument>(op)) {
        set.insert(op);
      }
    }
  }
}

void NestedIfNode::extractDirectDepVals() {
  std::stack<Instruction *> st;
  st.push(cond);
  while (!st.empty()) {

    Instruction *tmp = st.top();
    st.pop();
    if (!tmp)
      continue;
    BinaryOperator *bo;
    if (tmp->getType()->isIntegerTy(1) &&
        (bo = dyn_cast<BinaryOperator>(tmp))) {
      st.push(dyn_cast<Instruction>(bo->getOperand(0)));
      st.push(dyn_cast<Instruction>(bo->getOperand(1)));
    } else {
      for (auto &op : tmp->operands()) {
        /**
         * 处理特殊的 Cast指令
         */
        if (isa<Instruction>(op)) {
          if (op->getType()->isIntegerTy(1))
            continue;
          addInsn2vec(directDepVals, op)
        } else if (isa<GlobalVariable>(op) || isa<Argument>(op)) {
          directDepVals.push_back(op);
        }
      }
    }
  }
}

BranchInst *NestedIfNode::getBranchInsn() const { return br; }

const SmallVector<Value *, 8> &NestedIfNode::getDirectDepVals() const {
  return directDepVals;
}

NestedIfNode *NestedIfNode::getNestedIfHead() {
  return hoistBorder == nullptr ? root : hoistBorder;
}

static bool isDirectlyAffectedByPHI(BasicBlock *from, BasicBlock *to) {
  for (auto &phi : to->phis()) {
    int idx = phi.getBasicBlockIndex(from);
    if (idx != -1) {
      return true;
    }
  }
  return false;
}

NestedIfNode::NestedIfNode(NestedIfNode *parent, NestedIfNode *root,
                           BasicBlock *bb, BasicBlock *entry, BranchInst *br,
                           Instruction *cond, bool isThen)
    : parent(parent), root(root), hoistBorder(nullptr), bb(bb), entry(entry),
      br(br), cond(cond), thenBranch(isThen) {

  u32 then_id = next_edge_id();
  u32 else_id = next_edge_id();

  auto *Int32Ty = Type::getInt32Ty(bb->getContext());

  thenEdge = ConstantInt::get(Int32Ty, then_id);
  elseEdge = ConstantInt::get(Int32Ty, else_id);
  cmpSplit = isCmpSplit(bb);
}

NestedIfNode::NestedIfNode(BasicBlock *bb, BranchInst *br, Instruction *cond)
    : parent(nullptr), root(this), hoistBorder(nullptr), bb(bb), entry(bb),
      br(br), cond(cond) {

  u32 then_id = next_edge_id();
  u32 else_id = next_edge_id();

  auto *Int32Ty = Type::getInt32Ty(bb->getContext());

  thenEdge = ConstantInt::get(Int32Ty, then_id);
  elseEdge = ConstantInt::get(Int32Ty, else_id);
  cmpSplit = isCmpSplit(bb);
}

NestedIfNode::~NestedIfNode() {
  for (auto ifThen : ifThens) {
    delete ifThen;
  }
  ifThens.clear();
  for (auto ifElse : ifElses) {
    delete ifElse;
  }
  ifElses.clear();
}

bool NestedIfNode::isCompareSplit() const { return cmpSplit; }

NestedIfNode *NestedIfNode::getHoistBorder() const { return hoistBorder; }

void NestedIfNode::setHoistBorder(NestedIfNode *hoistBorder) {
  NestedIfNode::hoistBorder = hoistBorder;
}

NestedIfNode *NestedIfNode::createRootNode(BasicBlock *root) {
  BranchInst *term = dyn_cast<BranchInst>(root->getTerminator());
  if ((!term) || !term->isConditional())
    return nullptr;
  Instruction *cond = dyn_cast<Instruction>(term->getCondition());
  if (!cond)
    return nullptr;

  return new NestedIfNode(root, term, cond);
}

ConstantInt *NestedIfNode::getBrSrc() const { return brSrc; }

ConstantInt *NestedIfNode::getThenEdge() const { return thenEdge; }

ConstantInt *NestedIfNode::getElseEdge() const { return elseEdge; }

NestedIfNode *NestedIfNode::getRoot() const { return root; }

void NestedIfTree::modifyCovInstArg(BasicBlock *curBB, Value *cond, bool isThen) {

  if (CallInst *instFuncCall =
          dyn_cast<CallInst>(curBB->getFirstNonPHIOrDbgOrLifetime())) {
    Instruction *thenTerm, *elseTerm;
    SplitBlockAndInsertIfThenElse(cond, instFuncCall, &thenTerm, &elseTerm);
    if (isThen) {
      instFuncCall->moveBefore(thenTerm);
      CallInst *anotherCall = dyn_cast<CallInst>(instFuncCall->clone());
      if (ConstantInt *arg =
              dyn_cast<ConstantInt>(instFuncCall->getArgOperand(0))) {
        int num = arg->getSExtValue();
        auto *minusNum = ConstantInt::get(arg->getType(), -num, true);
        anotherCall->setArgOperand(0, minusNum);
        anotherCall->insertBefore(elseTerm);
      }
    } else {
      instFuncCall->moveBefore(elseTerm);
      CallInst *anotherCall = dyn_cast<CallInst>(instFuncCall->clone());
      if (ConstantInt *arg =
              dyn_cast<ConstantInt>(instFuncCall->getArgOperand(0))) {
        int num = arg->getSExtValue();
        auto *minusNum = ConstantInt::get(arg->getType(), -num, true);
        anotherCall->setArgOperand(0, minusNum);
        anotherCall->insertBefore(thenTerm);
      }
    }
  }
}

void NestedIfTree::markHoistBarrier() {

  SmallPtrSet<Value *, 16> hoistedInsnDepVals;
  std::stack<NestedIfNode *> st;
  st.push(root);

  while (!st.empty()) {
    NestedIfNode *ni = st.top();
    st.pop();
    if (ni == nullptr) {
      continue;
    }

    ni->extractDirectDepVals();

    for (NestedIfNode *ifElse : ni->getIfElses()) {
      st.push(ifElse);
    }

    for (NestedIfNode *ifThen : ni->getIfThens()) {
      st.push(ifThen);
    }

    if (ni->isRoot())
      continue;

    ni->extractHoistedInsnDepVals(hoistedInsnDepVals);

    NestedIfNode *parent = ni->getParent(), *cur = ni;

    if (ni->isCompareSplit()) {
      while (parent != nullptr) {
        if (!parent->isCompareSplit())
          break;
        if (isHoistBarrierBB(parent->getBB())) {
          ni->setHoistBorder(cur);
          break;
        }
        cur = parent;
        parent = parent->getParent();
      }
    }

    while (parent != nullptr) {

      if (hasIntersect(parent->getDirectDepVals(), hoistedInsnDepVals)) {
        ni->setHoistBorder(cur);

        break;
      }
      cur = parent;
      parent = parent->getParent();
    }
    if (!ni->getHoistBorder()) {
      ni->setHoistBorder(ni->getRoot());
    }

    hoistedInsnDepVals.clear();
  }
}

void NestedIfTree::doMutateIf() {
  if (!root->empty()) {
    markHoistBarrier();
    doRootHoist();
  }
  doSinkInstr();
}

void NestedIfTree::doRootHoist() {

  std::stack<NestedIfNode *> st;
  st.push(root);
  while (!st.empty()) {
    NestedIfNode *ni = st.top();
    st.pop();
    for (NestedIfNode *ifElse : ni->getIfElses()) {
      st.push(ifElse);
    }

    for (NestedIfNode *ifThen : ni->getIfThens()) {
      st.push(ifThen);
    }

    NestedIfNode *head = ni->getNestedIfHead();

    if (head && head != ni) {
      insnHoist(ni->getCond(), head->getBB());
    }
  }
}

void NestedIfTree::doSinkInstr() {
  std::stack<NestedIfNode *> st;
  st.push(root);

  // while (!st.empty()) {
  //   NestedIfNode *ni = st.top();
  //   st.pop();

  //   Instruction *cond = ni->getCond();
  //   for (NestedIfNode *ifElse : ni->getIfElses()) {
  //     st.push(ifElse);
  //   }

  //   for (NestedIfNode *ifThen : ni->getIfThens()) {
  //     st.push(ifThen);
  //   }

  //   ConstantInt *thenEdge = ni->getThenEdge(), *elseEdge = ni->getElseEdge();

  //   if (PhantomMode || IntegMode) {

  //     Instruction *insertPoint = cond->getNextNonDebugInstruction();

  //     if (!insertPoint) {

  //       if (auto invoke = dyn_cast<InvokeInst>(cond)) {
  //         BasicBlock *normalDest = invoke->getNormalDest();
  //         insertPoint = normalDest->getFirstNonPHIOrDbgOrLifetime();
  //       }
  //     }

  //     if (insertPoint) {
  //       if (isa<PHINode>(insertPoint)) {
  //         insertPoint =
  //             insertPoint->getParent()->getFirstNonPHIOrDbgOrLifetime();
  //       }
  //       while (isa<LandingPadInst>(insertPoint) ||
  //              isa<ExtractValueInst>(insertPoint)) {
  //         insertPoint = insertPoint->getNextNonDebugInstruction();
  //       }
  //       CallInst::Create(phantomFunc, {cond, thenEdge, elseEdge}, "",
  //                        insertPoint);
  //     }
  //   }

  //   if (SourceMode || IntegMode)
  //     CallInst::Create(sourceSinkFunc, {cond, thenEdge, elseEdge}, "",
  //                      ni->getBranchInsn());
  //   if (PinMode || IntegMode)
  //     taintSinkForBranch(ni);
  // }
}

NestedIfTree::NestedIfTree(NestedIfNode *root) : root(root) {}

NestedIfTree::~NestedIfTree() { delete root; }

NestedIfNode *NestedIfTree::getRoot() const { return root; }

void NestedIfTree::taintSinkForBranch(NestedIfNode *ni) {
  BranchInst *Br = ni->getBranchInsn();
  if (Br->isConditional() && Br->getNumSuccessors() == 2) {

    Instruction *Cond = ni->getCond();
    if (Cond && Cond->getType()->isIntegerTy()) {
      if (auto Cmp = dyn_cast<CmpInst>(Cond)) {
        Instruction *InsertPoint = Cmp->getNextNode();
        if (!InsertPoint)
          InsertPoint = Br;
        processCmpForTaintSink(Cmp, ni->getThenEdge(), ni->getElseEdge(),
                               InsertPoint, Br);
      } else {
        BasicBlock *tarBB = nullptr;
        if (auto invoke = dyn_cast<InvokeInst>(Cond)) {
          tarBB = invoke->getNormalDest();
        } else {
          tarBB = Cond->getParent();
        }

        Instruction *InsertPoint = tarBB ? tarBB->getTerminator() : nullptr;
        if (!InsertPoint) {
          InsertPoint = Br;
        }

        processBoolCmpForTaintSink(Cond, ni->getThenEdge(), ni->getElseEdge(),
                                   InsertPoint, Br);
      }
    }
  }
}

void NestedIfTree::processCmpForTaintSink(CmpInst *Cmp, ConstantInt *thenEdge,
                                      ConstantInt *elseEdge,
                                      Instruction *InsertPoint1,
                                      Instruction *InsertPoint2) {
  // Value *OpArg[2];
  // OpArg[0] = Cmp->getOperand(0);
  // OpArg[1] = Cmp->getOperand(1);
  // Type *OpType = OpArg[0]->getType();
  // if (!((OpType->isIntegerTy() && OpType->getIntegerBitWidth() <= 64) ||
  //       OpType->isFloatTy() || OpType->isDoubleTy() || OpType->isPointerTy())) {
  //   processBoolCmpForTaintSink(Cmp, thenEdge, elseEdge, InsertPoint1,
  //                              InsertPoint2);
  //   return;
  // }
  // int num_bytes = OpType->getScalarSizeInBits() / 8;
  // if (num_bytes == 0) {
  //   if (OpType->isPointerTy()) {
  //     num_bytes = 8;
  //   } else {
  //     return;
  //   }
  // }
  // IRBuilder<> IRB(InsertPoint1);

  // Value *SizeArg = ConstantInt::get(IRB.getInt32Ty(), num_bytes);
  // Value *CondExt = IRB.CreateZExt(Cmp, IRB.getInt32Ty());
  // SetNoSanitize(CondExt);
  // OpArg[0] = castArgType(IRB, OpArg[0]);
  // OpArg[1] = castArgType(IRB, OpArg[1]);

  // CallInst *ProxyCall =
  //     IRB.CreateCall(phantomDTASink, {thenEdge, elseEdge, CondExt, SizeArg,
  //                                     OpArg[0], OpArg[1]});
  // SetNoSanitize(ProxyCall);

  // IRB.SetInsertPoint(InsertPoint2);
  // ProxyCall = IRB.CreateCall(sourceDTASink, {thenEdge, elseEdge, CondExt,
  //                                            SizeArg, OpArg[0], OpArg[1]});
  // SetNoSanitize(ProxyCall);
}

void NestedIfTree::processBoolCmpForTaintSink(Value *Cond, ConstantInt *thenEdge,
                                          ConstantInt *elseEdge,
                                          Instruction *InsertPoint1,
                                          Instruction *InsertPoint2) {
//   if (!Cond->getType()->isIntegerTy() ||
//       Cond->getType()->getIntegerBitWidth() > 32)
//     return;
//   Value *OpArg[2];
//   OpArg[1] = ConstantInt::get(Int64Ty, 1);
//   IRBuilder<> IRB(InsertPoint1);

//   Value *SizeArg = ConstantInt::get(Int32Ty, 1);
//   Value *CondExt = IRB.CreateZExt(Cond, Int32Ty);
//   SetNoSanitize(CondExt);
//   OpArg[0] = IRB.CreateZExt(CondExt, Int64Ty);
//   SetNoSanitize(OpArg[0]);

//   CallInst *ProxyCall =
//       IRB.CreateCall(phantomDTASink, {thenEdge, elseEdge, CondExt, SizeArg,
//                                       OpArg[0], OpArg[1]});
//   SetNoSanitize(ProxyCall);

//   IRB.SetInsertPoint(InsertPoint2);
//   ProxyCall = IRB.CreateCall(sourceDTASink, {thenEdge, elseEdge, CondExt,
//                                              SizeArg, OpArg[0], OpArg[1]});
//   SetNoSanitize(ProxyCall);
}



NestedIfForeast::NestedIfForeast(DominatorTree *DT, PostDominatorTree *PDT) : DT(DT), PDT(PDT) {
  ::llvm::DT  = DT;
  ::llvm::PDT = PDT;
  DenseMap<BasicBlock *, NestedIfNode *> bb2node;
  std::stack<BasicBlock *> bbs;

  auto *entryBB = DT->getRootNode()->getBlock();

  for (auto node : post_order(DT->getRootNode()))
  {
      BasicBlock *BB = node->getBlock();
      if (BB != nullptr)
        bbs.push(BB);
  }
  while (!bbs.empty())
  {
      BasicBlock *BB = bbs.top(), *scopeHeader = entryBB;
      bbs.pop();
      
      Instruction *inst = (BB)->getTerminator();

      BranchInst *br;
      // TODO: support switch, etc...
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
              if (isThenSuccessor(parentNode->getBranchInsn(), BB))
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
              trees.emplace_back(new NestedIfTree(node));
          }
      }
  }
}


void setContextForAnalysis(DominatorTree *DT, PostDominatorTree *PDT, 
                           MemorySSA *MSSA, LoopInfo *LI) {
  ::llvm::DT  = DT;
  ::llvm::PDT = PDT;
  ::llvm::MSSA = MSSA;
  ::llvm::LI = LI;
}

}

