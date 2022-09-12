#include <llvm-10/llvm/ADT/ArrayRef.h>
#include <llvm-10/llvm/ADT/StringRef.h>
#include <llvm-10/llvm/Analysis/CGSCCPassManager.h>
#include <llvm-10/llvm/IR/PassManager.h>
#include <llvm-10/llvm/Transforms/Scalar/LoopPassManager.h>
#include "utils.h"

#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/ADT/SmallVector.h"
using namespace llvm;

PreservedAnalyses SimpleSimplifyCFGPass::run(Function &F, FunctionAnalysisManager &AM)
{

    SmallVector<BasicBlock *, 32> bb2remove;
    SmallVector<BasicBlock *, 32> uncondBr2remove;
    // auto &DT = AM.getResult<DominatorTreeAnalysis>(F);
    // DomTreeUpdater DTU(DT, DomTreeUpdater::UpdateStrategy::Lazy);

    for (auto &BB : F)
    {
        BasicBlock *B = &BB;
        ConstantFoldTerminator(B, true);
        auto pred = B->getSinglePredecessor();
        if (pred && pred->getSingleSuccessor())
        {
            bb2remove.push_back(B);
        }
    }

    for (auto BB : bb2remove)
    {
        MergeBasicBlockIntoOnlyPred(BB);
    }
    bb2remove.clear();

    for (auto &BB : F)
    {
        BasicBlock *B = &BB;
        BranchInst *br = dyn_cast<BranchInst>(B->getTerminator());
        if (!br || br->isConditional()) continue;
        if (
            B->getFirstNonPHIOrDbg()->isTerminator() &&
                 B != &(B->getParent()->getEntryBlock()))
        {
            bb2remove.push_back(B);
        }
    }
    for (auto BB : bb2remove)
    {
        TryToSimplifyUncondBranchFromEmptyBlock(BB);
    }
    bb2remove.clear();
    removeUnreachableBlocks(F);

    // PreservedAnalyses PA;
    // PA.preserve<DominatorTreeAnalysis>();
    // return PA;
    return PreservedAnalyses::none();
}



extern "C"::llvm::PassPluginLibraryInfo getPassPluginInfo() {
    const auto callback = [](PassBuilder &PB) {
        PB.registerPipelineStartEPCallback([&](ModulePassManager &MPM) {
            MPM.addPass(createModuleToFunctionPassAdaptor(SimpleSimplifyCFGPass()));
            return true;
        });
    };


    return {LLVM_PLUGIN_API_VERSION, "demo", "0.0.1", callback};
};

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return getPassPluginInfo();
}