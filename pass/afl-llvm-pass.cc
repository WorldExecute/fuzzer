/* Migrate afl-llvm-pass.so.cc to LLVM 12, which use the new pass manager. 
    the original source code : https://github.com/google/AFL/blob/master/llvm_mode/afl-llvm-pass.so.cc
 */

#define AFL_LLVM_PASS
#include "config.h"
#include "debug.h"

#include "Pass.h"

#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/PassManager.h>
#include <unistd.h>


namespace llvm {

PreservedAnalyses AFLCoveragePass::run(Module &M, ModuleAnalysisManager &MAM) {

    LLVMContext &C = M.getContext();

    IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

    /* Show a banner */

    char be_quiet = 0;

    if (isatty(2) && !getenv("AFL_QUIET")) {

        SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");

    } else be_quiet = 1;

    /* Decide instrumentation ratio */

    char* inst_ratio_str = getenv("AFL_INST_RATIO");
    unsigned int inst_ratio = 100;

    if (inst_ratio_str) {

        if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
            inst_ratio > 100)
        FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

    }

    /* Get globals for the SHM region and the previous location. Note that
        __afl_prev_loc is thread-local. */

    GlobalVariable *AFLMapPtr =
        new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                            GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

    GlobalVariable *AFLPrevLoc = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
        0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

    /* Instrument all the things! */

    int inst_blocks = 0;

    for (auto &F : M)
        for (auto &BB : F) {

        BasicBlock::iterator IP = BB.getFirstInsertionPt();
        IRBuilder<> IRB(&(*IP));

        if (AFL_R(100) >= inst_ratio) continue;

        /* Make up cur_loc */

        unsigned int cur_loc = AFL_R(MAP_SIZE);

        ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

        /* Load prev_loc */

        LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
        PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

        /* Load SHM pointer */

        LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
        MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *MapPtrIdx =
            IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

        /* Update bitmap */

        LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
        IRB.CreateStore(Incr, MapPtrIdx)
            ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        /* Set prev_loc to cur_loc >> 1 */

        StoreInst *Store =
            IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
        Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        inst_blocks++;

        }

    /* Say something nice. */

    if (!be_quiet) {

        if (!inst_blocks) WARNF("No instrumentation targets found.");
        else OKF("Instrumented %u locations (%s mode, ratio %u%%).",
                inst_blocks, getenv("AFL_HARDEN") ? "hardened" :
                ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) ?
                "ASAN/MSAN" : "non-hardened"), inst_ratio);

    }

    return PreservedAnalyses::none();
}

}
