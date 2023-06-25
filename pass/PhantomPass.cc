#include "Pass.h"
#include "utils.h"
#include "debug.h"
#include "NestedIf.hpp"

#include "llvm/IR/PassInstrumentation.h"
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>


namespace llvm {
    
static FunctionCallee phantomFunc;

// static DominatorTree        *DT;
// static PostDominatorTree    *PDT;
// static BasicBlock           *entryBB;
// static LoopInfo             *LI;
// static MemorySSA            *MSSA;
static u32 edgeCnt = 0;

static void prepare(Module &M)
{


    StoreInst       *Store;
    LoadInst        *Load;
    Function        *newFun;
    FunctionType    *funcType;
    BasicBlock      *entry;
    LoadInst        *MapPtr;

    IRBuilder<> IRB(M.getContext());




    Instruction *thenTerm, *elseTerm, *term;
    Value *Seg, *Bit, *SegEntry, *SegEntryPtr, *NotNegOne;

    GlobalVariable *PhantomBitmap =
        new GlobalVariable(M, PointerType::get(IRB.getInt8Ty(), 0), false,
                            GlobalValue::ExternalLinkage, 0, "__phantom_bitmap_ptr");
    GlobalVariable *CrashMask =
        new GlobalVariable(M, IRB.getInt8Ty(), false,
                            GlobalValue::ExternalLinkage, 0, "__crash_mask",
                            0, GlobalVariable::GeneralDynamicTLSModel, 0, true);

    funcType = FunctionType::get(IRB.getVoidTy(), {IRB.getInt1Ty(), IRB.getInt32Ty(), IRB.getInt32Ty()}, false);
    newFun = Function::Create(funcType, GlobalValue::InternalLinkage, PHANTOM_FUNC, M);
    entry = BasicBlock::Create(newFun->getContext(), "entry", newFun);
    IRB.SetInsertPoint(entry);

    Argument *cond = newFun->getArg(0),
                *thenEdge = newFun->getArg(1),
                *elseEdge = newFun->getArg(2);

    Store = IRB.CreateStore(IRB.getInt8(255), CrashMask);
    SetNoSanitize(Store);
    IRB.CreateRet(nullptr);

    SplitBlockAndInsertIfThenElse(cond, Store, &thenTerm, &elseTerm);
    {
        IRB.SetInsertPoint(thenTerm);
        NotNegOne = IRB.CreateICmpNE(thenEdge, IRB.getInt32(-1));
        term = SplitBlockAndInsertIfThen(NotNegOne, thenTerm, false);
        {
            IRB.SetInsertPoint(term);

            Seg = IRB.CreateZExt(IRB.CreateLShr(thenEdge, IRB.getInt32(3), "seg"), IRB.getInt64Ty());
            Bit = IRB.CreateTrunc(IRB.CreateShl(IRB.getInt32(1), IRB.CreateAnd(thenEdge, IRB.getInt32(7)), "bit"), IRB.getInt8Ty());
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
        NotNegOne = IRB.CreateICmpNE(elseEdge, IRB.getInt32(-1));
        term = SplitBlockAndInsertIfThen(NotNegOne, elseTerm, false);
        {
            IRB.SetInsertPoint(term);

            Seg = IRB.CreateZExt(IRB.CreateLShr(elseEdge, IRB.getInt32(3), "seg"), IRB.getInt64Ty());
            Bit = IRB.CreateTrunc(IRB.CreateShl(IRB.getInt32(1), IRB.CreateAnd(elseEdge, IRB.getInt32(7)), "bit"), IRB.getInt8Ty());
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

static void doSinkInstr(NestedIfTree *niTree) {
  std::stack<NestedIfNode *> st;
  st.push(niTree->getRoot());

  while (!st.empty()) {
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
        edgeCnt += 2;
        CallInst::Create(phantomFunc, {cond, thenEdge, elseEdge}, "",
                            insertPoint);
    }

  }
}

PreservedAnalyses PhantomPass::run(Module &M, ModuleAnalysisManager &MAM) {

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
    SAYF(cCYA "phantom-pass " cBRI VERSION cRST " finished: " cBRI "%u" cRST " edges!\n", edgeCnt);
    return PreservedAnalyses::none();
}

}