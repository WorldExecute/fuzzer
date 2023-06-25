#include "utils.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Mem2Reg.h"
#include "llvm/Transforms/Scalar/LICM.h"
#include "llvm/Transforms/Scalar/EarlyCSE.h"
#include "llvm/Transforms/Scalar/SimplifyCFG.h"
#include "llvm/Transforms/InstCombine/InstCombine.h"
#include "llvm/Transforms/IPO/InferFunctionAttrs.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Pass.h"
#include "llvm/Analysis/ValueTracking.h"

#include "llvm/Analysis/CGSCCPassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include <unistd.h>


#include "Pass.h"
using namespace llvm;

void commonModuleTransform(Module &M, bool NoLaf)
{
    
    // Create the analysis managers.
    LoopAnalysisManager LAM;
    FunctionAnalysisManager FAM;
    CGSCCAnalysisManager CGAM;
    ModuleAnalysisManager MAM;
    
    // Create the new pass manager builder.
    // Take a look at the PassBuilder constructor parameters for more
    // customization, e.g. specifying a TargetMachine or various debugging
    // options.
    PassBuilder PB;

    // Register all the basic analyses with the managers.
    PB.registerModuleAnalyses(MAM);
    PB.registerCGSCCAnalyses(CGAM);
    PB.registerFunctionAnalyses(FAM);
    PB.registerLoopAnalyses(LAM);
    PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

    FunctionPassManager FPM;
    ModulePassManager MPM;
    // FPM.addPass(SimplifyCFGPass());
    FPM.addPass(PromotePass());
    FPM.addPass(InstCombinePass(true));
    FPM.addPass(EarlyCSEPass(true));
    FPM.addPass(createFunctionToLoopPassAdaptor(LICMPass(), true));
    llvm::errs() << "Running simple-simplify-CFG-pass\n";
    // FPM.addPass(SimpleSimplifyCFGPass());

    MPM.addPass(InferFunctionAttrsPass());
    MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
    if (!NoLaf) {
        MPM.addPass(SplitNByteCmpPass());
        MPM.addPass(SplitFuncCmpPass());
        MPM.addPass(SplitSwitchPass());
    }
    MPM.addPass(createModuleToFunctionPassAdaptor(PromotePass()));
    // MPM.addPass(createModuleToFunctionPassAdaptor(EarlyCSEPass(true)));

    MPM.run(M, MAM);
}



// LTO : link time optimization, 链接时优化
void doO3Optimization(Module &M, bool DebugLogging, bool LTOPreLink) {
        // Create the analysis managers.
    LoopAnalysisManager LAM;
    FunctionAnalysisManager FAM;
    CGSCCAnalysisManager CGAM;
    ModuleAnalysisManager MAM;

    // Create the new pass manager builder.
    // Take a look at the PassBuilder constructor parameters for more
    // customization, e.g. specifying a TargetMachine or various debugging
    // options.
    PassBuilder PB;

    // Register all the basic analyses with the managers.
    PB.registerModuleAnalyses(MAM);
    PB.registerCGSCCAnalyses(CGAM);
    PB.registerFunctionAnalyses(FAM);
    PB.registerLoopAnalyses(LAM);
    PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

    ModulePassManager MPM = PB.buildPerModuleDefaultPipeline(llvm::PassBuilder::OptimizationLevel::O3, LTOPreLink);
    MPM.run(M, MAM);
}

/**
 * @brief Get the Module Name, differential by absolute path.
 * 
 * @param M 
 * @return std::string 
 */
std::string getUniqModuleName(Module& M) {
    std::string mName = M.getName().str();

    char num[11];
    sprintf(num, "%u", M.getInstructionCount());
    mName += "-";
    mName += num; 
    char *pwd = get_current_dir_name();
    mName = "#" + mName;
    mName = pwd + mName;
    std::replace(mName.begin(), mName.end(), '\\', '/');
    std::replace(mName.begin(), mName.end(), '/', '#');
    return mName;
}


bool checkFunctionInWhiteList(Function *F) {
    return false;
}

bool isSanitizeFunc(Function *F) {
    StringRef name = F->getName();
    return name.startswith("asan.") || name.startswith("msan.") ;
}

bool isBlacklisted(llvm::Function *F) {
    return false;
}

Value *castArgType(IRBuilder<> &IRB, Value *V)
{
    Type *OpType = V->getType();
    Value *NV = V;
    if (OpType->isFloatTy())
    {
        NV = IRB.CreateFPToUI(V, IRB.getInt32Ty());
        SetNoSanitize(NV);
        NV = IRB.CreateIntCast(NV, IRB.getInt64Ty(), false);
        SetNoSanitize(NV);
    }
    else if (OpType->isDoubleTy())
    {
        NV = IRB.CreateFPToUI(V, IRB.getInt64Ty());
        SetNoSanitize(NV);
    }
    else if (OpType->isPointerTy())
    {
        NV = IRB.CreatePtrToInt(V, IRB.getInt64Ty());
    }
    else
    {
        if (OpType->isIntegerTy() && OpType->getIntegerBitWidth() < 64)
        {
            NV = IRB.CreateZExt(V, IRB.getInt64Ty());
        }
    }
    return NV;
}
