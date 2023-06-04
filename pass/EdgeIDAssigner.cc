#include "Pass.h"
#include "llvm/IR/Instructions.h"


static inline int nextID() {
    static int id = 0;
    return (id++) % 0xffff;
}

namespace llvm {

EdgeIDAssigner::Result EdgeIDAssigner::run(Module &M, ModuleAnalysisManager &MAM) {
    Result result;
    for (auto &F : M) {
        for (auto &BB : F) {
            for (auto &I : BB) {
                if (auto *br = dyn_cast<BranchInst>(&I)) {
                    if (br->isConditional()) {
                        result[{&BB, br->getSuccessor(0)}] = nextID();
                        result[{&BB, br->getSuccessor(1)}] = nextID();
                    }
                }
            }
        }
    }
    return result;
}

}