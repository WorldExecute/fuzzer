#pragma once


#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Module.h"
#include <llvm/IR/PassManager.h>
#include <utility>


// Some analysis pass
namespace llvm {

/* 
 * @brief The analysis pass to assign a unique ID to each basic block
 * 
 * The ID is assigned in the order of the iteration of the basic blocks.
 * 
 */
class BasicBlockIDAssigner : public AnalysisInfoMixin<BasicBlockIDAssigner> {
public:
    using Result = DenseMap<const BasicBlock *, int>;
private:
    static AnalysisKey Key;
    friend struct AnalysisInfoMixin<BasicBlockIDAssigner>;

public:
    BasicBlockIDAssigner() {}
    Result run(Module &M, ModuleAnalysisManager &MAM);

    static bool isRequired() { return true; }
};


/* 
 * @brief The analysis pass to assign a unique ID to each branch edge.
 * 
 */
class EdgeIDAssigner : public AnalysisInfoMixin<EdgeIDAssigner> {
public:
    using Result = DenseMap<std::pair<const BasicBlock *, const BasicBlock *>, int>;
private:
    static AnalysisKey Key;
    friend struct AnalysisInfoMixin<EdgeIDAssigner>;

public:
    EdgeIDAssigner() {}
    Result run(Module &M, ModuleAnalysisManager &MAM);

    static bool isRequired() { return true; }
};

}

// Some transformation pass
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

class MirageTransformPass : public PassInfoMixin<MirageTransformPass> {
public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager MAM);
};

class AFLSourcePass : public PassInfoMixin<AFLSourcePass> {
public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager MAM);
};

class TaintSinkPass : public PassInfoMixin<TaintSinkPass> {
public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager MAM);
};

}