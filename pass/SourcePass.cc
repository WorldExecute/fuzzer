#include "Pass.h"
#include "debug.h"
#include "utils.h"
#include "NestedIf.hpp"

#include "llvm/IR/PassInstrumentation.h"
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>

namespace llvm {

static FunctionCallee sourceFunc;

// static DominatorTree        *DT;
// static PostDominatorTree    *PDT;
// static BasicBlock           *entryBB;
// static LoopInfo             *LI;
// static MemorySSA            *MSSA;

static u32 edgeCnt = 0;

static void prepare(Module &M)
{
    LLVMContext &C = M.getContext();


    StoreInst *Store;
    Function *newFun;
    FunctionType *funcType;
    BasicBlock *entry;
    ReturnInst *ret;
    LoadInst *MapPtr;

    IRBuilder<> IRB(M.getContext());




    Instruction *thenTerm, *elseTerm, *term;
    Value *NotNegOne;

    GlobalVariable *SourceMapPtr =
        new GlobalVariable(M, PointerType::get(IRB.getInt8Ty(), 0), false,
                            GlobalValue::ExternalLinkage, 0, "__source_map_ptr");

    funcType = FunctionType::get(Type::getVoidTy(C), {IRB.getInt1Ty(), IRB.getInt32Ty(), IRB.getInt32Ty()}, false);
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
            NotNegOne = IRB.CreateICmpNE(thenEdge, IRB.getInt32(-1));
            term = SplitBlockAndInsertIfThen(NotNegOne, thenTerm, false);
            IRB.SetInsertPoint(term);

            MapPtr = IRB.CreateLoad(SourceMapPtr);
            SetNoSanitize(MapPtr);

            SourceEntryPtr = IRB.CreateGEP(MapPtr, IRB.CreateZExt(thenEdge, IRB.getInt64Ty()));
            Store = IRB.CreateStore(IRB.getInt8(255), SourceEntryPtr);
            SetNoSanitize(Store);
        }
        IRB.SetInsertPoint(thenTerm);
        {
            NotNegOne = IRB.CreateICmpNE(elseEdge, IRB.getInt32(-1));
            term = SplitBlockAndInsertIfThen(NotNegOne, thenTerm, false);
            IRB.SetInsertPoint(term);

            MapPtr = IRB.CreateLoad(SourceMapPtr);
            SetNoSanitize(MapPtr);
            SourceEntryPtr = IRB.CreateGEP(MapPtr, IRB.CreateZExt(elseEdge, IRB.getInt64Ty()));
            SourceEntry = IRB.CreateLoad(SourceEntryPtr);
            SetNoSanitize(SourceEntry);
            Store = IRB.CreateStore(IRB.CreateOr(SourceEntry, IRB.getInt8(1)), SourceEntryPtr);
            SetNoSanitize(Store);
        }
    }

    {
        IRB.SetInsertPoint(elseTerm);
        {
            NotNegOne = IRB.CreateICmpNE(elseEdge, IRB.getInt32(-1));
            term = SplitBlockAndInsertIfThen(NotNegOne, elseTerm, false);
            IRB.SetInsertPoint(term);

            MapPtr = IRB.CreateLoad(SourceMapPtr);
            SetNoSanitize(MapPtr);
            SourceEntryPtr = IRB.CreateGEP(MapPtr, IRB.CreateZExt(elseEdge, IRB.getInt64Ty()));
            Store = IRB.CreateStore(IRB.getInt8(255), SourceEntryPtr);
            SetNoSanitize(Store);
        }
        IRB.SetInsertPoint(elseTerm);
        {
            NotNegOne = IRB.CreateICmpNE(thenEdge, IRB.getInt32(-1));
            term = SplitBlockAndInsertIfThen(NotNegOne, elseTerm, false);
            IRB.SetInsertPoint(term);

            MapPtr = IRB.CreateLoad(SourceMapPtr);
            SetNoSanitize(MapPtr);
            SourceEntryPtr = IRB.CreateGEP(MapPtr, IRB.CreateZExt(thenEdge, IRB.getInt64Ty()));
            SourceEntry = IRB.CreateLoad(SourceEntryPtr);
            SetNoSanitize(SourceEntry);
            Store = IRB.CreateStore(IRB.CreateOr(SourceEntry, IRB.getInt8(2)), SourceEntryPtr);
            SetNoSanitize(Store);
        }
    }

    SetFuncMetadata(newFun, INSTRUMENT);
    sourceFunc = newFun;

}

static void doSinkInstr(NestedIfTree *niTree) {
  std::stack<NestedIfNode *> st;
  st.push(niTree->getRoot());

  while (!st.empty()) {
    NestedIfNode *ni = st.top();
    st.pop();

    Instruction *cond = ni->getCond();
    for (NestedIfNode *ifElse : ni->getIfElses()) {
      st.push(ifElse);
    }

    for (NestedIfNode *ifThen : ni->getIfThens()) {
      st.push(ifThen);
    }

    ConstantInt *thenEdge = ni->getThenEdge(), *elseEdge = ni->getElseEdge();

    edgeCnt+= 2;
    CallInst::Create(sourceFunc, {cond, thenEdge, elseEdge}, "",
                       ni->getBranchInsn());

  }
}


PreservedAnalyses SourcePass::run(Module &M, ModuleAnalysisManager &MAM) {
    auto &niForestMap = MAM.getResult<NestedIfAnalysis>(M);

    prepare(M);
    for (auto &[func, niForest] : niForestMap) {
        for (auto &niTree : *niForest) {
            doSinkInstr(niTree);
        }
    }
    SAYF(cCYA "source-pass " cBRI VERSION cRST " finished: " cBRI "%u" cRST " edges!\n", edgeCnt);
    return PreservedAnalyses::none();
}

}