#ifndef _TRANSFORM_H
#define _TRANSFORM_H


#include <algorithm>
#include <cstring>

#include "llvm/IR/Module.h"
#include "llvm/Transforms/Scalar/LICM.h"

#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/AliasSetTracker.h"
#include "llvm/Analysis/CaptureTracking.h"
#include "llvm/Analysis/ConstantFolding.h"
#include "llvm/Analysis/GuardUtils.h"
#include "llvm/Analysis/LazyBlockFrequencyInfo.h"
#include "llvm/Analysis/Loads.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/LoopIterator.h"
#include "llvm/Analysis/LoopPass.h"
#include "llvm/Analysis/MemorySSA.h"
#include "llvm/Analysis/MemorySSAUpdater.h"
#include "llvm/Analysis/MustExecute.h"
#include "llvm/Analysis/OptimizationRemarkEmitter.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/TargetTransformInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/PatternMatch.h"
#include "llvm/IR/PredIteratorCache.h"
#include "llvm/InitializePasses.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/LoopUtils.h"
#include "llvm/Transforms/Utils/SSAUpdater.h"

// #define DEBUG 1

#define INSTRUMENT "__INSTRUMENT__"

#define NOSANITIZE "nosanitize"
#define COV_FUNC "__ts__coverage_collect__"
#define PHANTOM_FUNC "__ts__phantom_sink__"
#define SOURCE_FUNC "__ts__source_sink__"
#define TAINT_FUNC "__ts_trace_simple_br_cmp_tt"
#define SOURCE_TAINT_FUNC "__ts_trace_simple_br_cmp_tt"
#define PHANTOM_TAINT_FUNC "__ts_trace_simple_phantom_cmp_tt"


#define isInWhiteList(call) (\
        (call) &&\
        (call)->getCalledFunction() &&\
        ( \
            (call)->getCalledFunction()->getName().startswith("__ts__") \
            ||  (call)->getCalledFunction()->getName().equals("printf") \
            ||  (call)->getCalledFunction()->getName().equals("puts") \
        ) \
    ) 

#define HOIST_BANNER "stop_hoist"
#define ARGV_RELATED "__argv_related__"
#define SKIP "__skip__"
#define CMP_THEN "__cmp_then__"
#define CMP_ELSE "__cmp_else__"
#define CMP_OP "__cmp_op__"
#define CMP_SPLIT "__cmp_split__"

#define SetNoSanitize(insn) SetMetadata(insn, NOSANITIZE)
#define SetHoistBanner(BB)  BB->getTerminator()->setMetadata(HOIST_BANNER, MDNode::get(BB->getContext(), None))
#define SetCmpThen(br)  br->setMetadata(CMP_THEN, MDNode::get(br->getContext(), None))
#define SetCmpElse(br)  br->setMetadata(CMP_ELSE, MDNode::get(br->getContext(), None))
#define SetMetadata(target, meta)  if(Instruction *ins = dyn_cast<Instruction>(target)) ins->setMetadata(meta, MDNode::get(ins->getContext(), None))
#define SetFuncMetadata(target, meta)  (target)->setMetadata(meta, MDNode::get((target)->getContext(), None))
#define SetBBMetadata(bb, meta)  bb->getTerminator()->setMetadata(meta, MDNode::get(bb->getContext(), None))

#define isFuncOwnMetadata(func, meta) ((func)->getMetadata(meta) != nullptr)
#define isBBOwnMetadata(bb, metadata) ((bb)->getTerminator()->getMetadata((metadata)) != nullptr)
#define isInsnOwnMetadata(insn, metadata) ((insn)->getMetadata((metadata)) != nullptr)

#define isFuncShouldSkip(func) (isFuncOwnMetadata((func), INSTRUMENT) || (func)->isDeclaration())

#define isSanitizeInsn(insn) ((insn)->getMetadata(NOSANITIZE) != nullptr)
#define isSanitizeBB(bb) ((bb)->getTerminator()->getMetadata(NOSANITIZE) != nullptr)

#define isHoistBarrierBB(bb) (bb->getTerminator()->getMetadata(HOIST_BANNER) != nullptr)
#define isNotHoistBarrierBB(bb) (bb->getTerminator()->getMetadata(HOIST_BANNER) == nullptr)
#define isNotCmpSplit(bb) (bb->getTerminator()->getMetadata(CMP_SPLIT) == nullptr)
#define isCmpSplit(bb) (bb->getTerminator()->getMetadata(CMP_SPLIT) != nullptr)
#define isCmpThen(bb) (bb->getTerminator()->getMetadata(CMP_THEN) != nullptr)
#define isCmpElse(bb) (bb->getTerminator()->getMetadata(CMP_ELSE) != nullptr)
#define isCmpBranch(bb) (isCmpThen(bb) || isCmpElse(bb))
#define isInsnHasCmpOp(insn) (insn->getMetadata(CMP_OP) != nullptr)

using namespace llvm;

namespace llvm {
    class SplitFuncCmpPass : public PassInfoMixin<SplitFuncCmpPass> {
    public:
        PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
    };

    class SplitNByteCmpPass : public PassInfoMixin<SplitNByteCmpPass> {
    public:
        PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
    };

    class SplitSwitchPass : public PassInfoMixin<SplitSwitchPass> {
    public:
        PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
    };

    /**
     * @brief The simplified version of the official SimplifyCFGPass
     * 
     * The official SimplifyCFGPass would do lots of mirage optimizations on CFG simplification, some of which damage the semanitic of fuzzing. 
     * Hence, a new simple SimplifyCFGPass is on demand, which eliminates the BB in the premise of fuzzing sematic being unchanged.
     * 
     */
    class SimpleSimplifyCFGPass : public PassInfoMixin<SimpleSimplifyCFGPass> {
    public:
        PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
        
        // /**
        // * 不会被跳过， 即使是 optnone
        // */
        // static bool isRequired() { return true; }
    };
}

bool checkFunctionInWhiteList(Function *F);

void commonModuleTransform(Module &, bool);
void doO3Optimization(Module &M, bool DebugLogging, bool LTOPreLink);
std::string getModuleName(Module& M);

bool isSanitizeFunc(Function *F);

//bool promoteMemoryToRegister(Function &F, DominatorTree &DT,
//                             AssumptionCache &AC);

//void doLICM(Loop *L, AAResultsWrapperPass *AA,
//            LoopInfo *LI, DominatorTree *DT,
//            LazyBlockFrequencyInfoPass *BFIP,
//            TargetLibraryInfo *TLI,
//            TargetTransformInfo *TTI,
//            ScalarEvolutionWrapperPass *SE,
//            MemorySSA *MSSA);

#endif