#include "Pass.h"
#include "utils.h"
#include "debug.h"
#include "NestedIf.hpp"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/PassInstrumentation.h"
#include <llvm/Support/raw_ostream.h>





namespace llvm {

static FunctionCallee phantomDTASink,
                      sourceDTASink;

static void prepare(Module &M)
{
    LLVMContext &C = M.getContext();


    /* Get globals for the SHM region and the previous location. Note that
       __afl_prev_loc is thread-local. */

    IRBuilder<> IRB(M.getContext());

    auto *funcType = FunctionType::get(IRB.getVoidTy(), 
                {IRB.getInt32Ty(), IRB.getInt32Ty(), IRB.getInt32Ty(), IRB.getInt32Ty(), IRB.getInt64Ty(), IRB.getInt64Ty()}, 
                false);
    AttributeList AL;
    AL = AL.addAttribute(C, AttributeList::FunctionIndex, Attribute::NoUnwind);
    sourceDTASink = M.getOrInsertFunction(SOURCE_TAINT_FUNC, funcType, AL);
    phantomDTASink = M.getOrInsertFunction(PHANTOM_TAINT_FUNC, funcType, AL);
    
}


static void processBoolCmpForTaintSink(Value *Cond, ConstantInt *thenEdge, ConstantInt *elseEdge,
                                          Instruction *InsertPoint1, Instruction *InsertPoint2)
{
    if (!Cond->getType()->isIntegerTy() ||
        Cond->getType()->getIntegerBitWidth() > 32)
        return;
    IRBuilder<> IRB(InsertPoint1);
    Value *OpArg[2];
    OpArg[1] = ConstantInt::get(IRB.getInt64Ty(), 1);

    Value *SizeArg = ConstantInt::get(IRB.getInt32Ty(), 1);
    Value *CondExt = IRB.CreateZExt(Cond, IRB.getInt32Ty());
    SetNoSanitize(CondExt);
    OpArg[0] = IRB.CreateZExt(CondExt, IRB.getInt64Ty());
    SetNoSanitize(OpArg[0]);

    CallInst *ProxyCall =
        IRB.CreateCall(phantomDTASink, {thenEdge, elseEdge, CondExt, SizeArg, OpArg[0], OpArg[1]});
    SetNoSanitize(ProxyCall);

    IRB.SetInsertPoint(InsertPoint2);
    ProxyCall =
        IRB.CreateCall(sourceDTASink, {thenEdge, elseEdge, CondExt, SizeArg, OpArg[0], OpArg[1]});
    SetNoSanitize(ProxyCall);
}


static void processCmpForTaintSink(CmpInst *Cmp, ConstantInt *thenEdge,
                                      ConstantInt *elseEdge,
                                      Instruction *InsertPoint1,
                                      Instruction *InsertPoint2) {
  Value *OpArg[2];
  OpArg[0] = Cmp->getOperand(0);
  OpArg[1] = Cmp->getOperand(1);
  Type *OpType = OpArg[0]->getType();
  if (!((OpType->isIntegerTy() && OpType->getIntegerBitWidth() <= 64) ||
        OpType->isFloatTy() || OpType->isDoubleTy() || OpType->isPointerTy())) {
    processBoolCmpForTaintSink(Cmp, thenEdge, elseEdge, InsertPoint1,
                               InsertPoint2);
    return;
  }
  int num_bytes = OpType->getScalarSizeInBits() / 8;
  if (num_bytes == 0) {
    if (OpType->isPointerTy()) {
      num_bytes = 8;
    } else {
      return;
    }
  }
  IRBuilder<> IRB(InsertPoint1);

  Value *SizeArg = ConstantInt::get(IRB.getInt32Ty(), num_bytes);
  Value *CondExt = IRB.CreateZExt(Cmp, IRB.getInt32Ty());
  SetNoSanitize(CondExt);
  OpArg[0] = castArgType(IRB, OpArg[0]);
  OpArg[1] = castArgType(IRB, OpArg[1]);

  CallInst *ProxyCall =
      IRB.CreateCall(phantomDTASink, {thenEdge, elseEdge, CondExt, SizeArg,
                                      OpArg[0], OpArg[1]});
  SetNoSanitize(ProxyCall);

  IRB.SetInsertPoint(InsertPoint2);
  ProxyCall = IRB.CreateCall(sourceDTASink, {thenEdge, elseEdge, CondExt,
                                             SizeArg, OpArg[0], OpArg[1]});
  SetNoSanitize(ProxyCall);
}


static void taintSinkForBranch(NestedIfNode *ni) {
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


static void doSinkInstr(NestedIfTree *niTree) {
  NestedIfNode *root = niTree->getRoot();
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

    taintSinkForBranch(ni);
  }
}


PreservedAnalyses TaintSinkPass::run(Module &M, ModuleAnalysisManager &MAM) {
    SAYF(cCYA "taint-sink-pass " cBRI VERSION cRST "\n");

    auto &niForestMap = MAM.getResult<NestedIfAnalysis>(M);
    auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();

    prepare(M);
    for (auto &[func, niForest] : niForestMap) {
        auto *MSSA = &FAM.getResult<MemorySSAAnalysis>(*func).getMSSA();
        auto *LI   = &FAM.getResult<LoopAnalysis>(*func);
        auto *DT   = &FAM.getResult<DominatorTreeAnalysis>(*func);
        auto *PDT  = &FAM.getResult<PostDominatorTreeAnalysis>(*func);
        setContextForAnalysis(DT, PDT, MSSA, LI);
        for (auto &niTree : *niForest) {
            niTree->markHoistBarrier();
            niTree->doRootHoist();
            doSinkInstr(niTree);
        }
    }
    return PreservedAnalyses::none();
}


}