#include "Pass.h"
#include "llvm/IR/PassInstrumentation.h"

namespace llvm {

PreservedAnalyses TaintSinkPass::run(Module &M, ModuleAnalysisManager MAM) {
    return PreservedAnalyses::none();
}


}