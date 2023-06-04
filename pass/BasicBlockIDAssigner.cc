#include "Pass.h"

// Some analysis pass
namespace llvm {

BasicBlockIDAssigner::Result BasicBlockIDAssigner::run(Module &M, ModuleAnalysisManager &MAM) {
    Result result;
    int id = 0;
    for (auto &F : M) {
        for (auto &BB : F) {
            result[&BB] = id++;
        }
    }
    return result;
}

}