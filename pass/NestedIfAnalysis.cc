#include "Pass.h"
#include "utils.h"

#include "NestedIf.hpp"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/raw_ostream.h"

namespace llvm {

AnalysisKey NestedIfAnalysis::Key;


NestedIfAnalysis::Result NestedIfAnalysis::run(Module &M, ModuleAnalysisManager &MAM) {
    Result map;
    auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
    for (auto &F: M) {
        if (F.isDeclaration() || F.isIntrinsic() || isBlacklisted(&F)) {
            continue;
        }
        DominatorTree     *DT  = &FAM.getResult<DominatorTreeAnalysis>(F);
        PostDominatorTree *PDT = &FAM.getResult<PostDominatorTreeAnalysis>(F);
        auto *NestedIfForeast = new class NestedIfForeast(DT, PDT);
        map[&F] = NestedIfForeast;
    }
    return map;
}

}