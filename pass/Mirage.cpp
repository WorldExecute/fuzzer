/*
  An entrypoint to do instrumentation and transformation.
 
  Author: Kunqiu Chen
 */

#include "Pass.h"

#include <unistd.h>

#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/Transforms/IPO/InferFunctionAttrs.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Transforms/Scalar/EarlyCSE.h>
#include <llvm/Transforms/Scalar/LICM.h>
#include <llvm/Transforms/Utils/Mem2Reg.h>
#include <cstddef>
#include <cstdlib>
#include <functional>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/raw_ostream.h>
#include <string>

#include <llvm/IR/PassManager.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Transforms/Utils/UnifyFunctionExitNodes.h>
#include <llvm/Transforms/Scalar/SimplifyCFG.h>
#include <llvm/IRReader/IRReader.h>
// #include <header>

namespace llvm {

static cl::opt<bool> UseLaf("laf", cl::ZeroOrMore,
                               cl::desc("LafIntel Mode. Default: true"),
                               cl::value_desc("laf"), cl::init(true));

// static cl::opt<std::string>
//     OutDirectory("outdir", cl::ZeroOrMore,
//                  cl::desc("Output directory where Ftargets.txt, Fnames.txt, "
//                           "and BBnames.txt are generated."),
//                  cl::value_desc("outdir"), cl::init(""));

// static cl::opt<bool> ReduceICFG("reduce", cl::ZeroOrMore,
//                                 cl::desc("Enable SimpleICFG reduction."),
//                                 cl::value_desc("reduce"), cl::init(false));

// static cl::opt<bool> AFLGo("aflgo", cl::ZeroOrMore,
//                            cl::desc("Do AFLGo preprocessing."),
//                            cl::value_desc("aflgo"), cl::init(false));

// static cl::opt<std::string>
//     InputFilename(cl::Positional, cl::desc("<input bitcode>"), cl::init("-"));
} // namespace llvm


static void writeLLVMModuleToFile(llvm::Module &M, std::string suffix) {
        std::string moduleName = M.getName().str();
        std::string OutputFilename;
        std::size_t pos = moduleName.rfind('.');
        if (pos != std::string::npos)
            OutputFilename = moduleName.substr(0, pos) + suffix;
        else
            OutputFilename = moduleName + suffix;

        std::error_code EC;
        llvm::raw_fd_ostream OS(OutputFilename.c_str(), EC, llvm::sys::fs::OF_None);
        
#if (LLVM_VERSION_MAJOR >= 7)
        WriteBitcodeToFile(M, OS);
#else
        WriteBitcodeToFile(&M, OS);
#endif


}


using namespace llvm;
int main(int argc, char **argv) {


  // SVFModule *svfModule =
  //     LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(moduleNameVec);

  // svfModule->buildSymbolTableInfo();
  LLVMContext C;
  SMDiagnostic Err;
  std::string file = "demo.ll";
  std::unique_ptr<Module> mod = parseIRFile(file, Err, C);


  llvm::PassBuilder PB;

  // Create the analysis managers.
  llvm::LoopAnalysisManager LAM;
  llvm::FunctionAnalysisManager FAM;
  llvm::CGSCCAnalysisManager CGAM;
  llvm::ModuleAnalysisManager MAM;

  // Register all the basic analyses with the managers.
  PB.registerModuleAnalyses(MAM);
  PB.registerCGSCCAnalyses(CGAM);
  PB.registerFunctionAnalyses(FAM);
  PB.registerLoopAnalyses(LAM);
  PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

  llvm::ModulePassManager MPM;
  llvm::FunctionPassManager FPM;

  // MPM.addPass(createModuleToFunctionPassAdaptor(llvm::SimplifyCFGPass()));
  FPM.addPass(PromotePass());
  // Let splitCmp Pass identify the constant value
  FPM.addPass(InstCombinePass(true));
  FPM.addPass(EarlyCSEPass(true));
  FPM.addPass(createFunctionToLoopPassAdaptor(LICMPass(), true));
  llvm::errs() << "Running simple-simplify-CFG-pass by me\n";
  // FPM.addPass(SimpleSimplifyCFGPass());

  MPM.addPass(InferFunctionAttrsPass());
  MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
  // FPM.addPass(llvm::SimpleSimplifyCFGPass());
  if (!UseLaf) {
      MPM.addPass(SplitNByteCmpPass());
      MPM.addPass(SplitFuncCmpPass());
      MPM.addPass(SplitSwitchPass());
  }
  MPM.addPass(createModuleToFunctionPassAdaptor(PromotePass()));
  
  // Trigger ID assigner in advance
  MPM.addPass(RequireAnalysisPass<EdgeIDAssigner, Module>());

  MAM.registerPass([] { return EdgeIDAssigner(); });

  MPM.run(*mod, MAM);

  writeLLVMModuleToFile(*mod, ".raw.bc");

  // Forks 3 processes to share the analysis and do the following:
  //  1. Mirage Pass
  //  2. AFLSource Pass
  //  3. TaintSink Pass
  const char *suffix;
  auto pid = fork();
  if (pid == 0) {
    // Child process
    llvm::ModulePassManager MPM1;

    // Mirage Pass
    llvm::errs() << "Running Mirage Pass\n";
    MPM1.addPass(MirageTransformPass());
    MPM1.run(*mod, MAM);
    suffix = ".mirage.bc";
    
    goto exit_point;
  } 

  pid = fork();
  if (pid == 0) {
    // Child process
    llvm::ModulePassManager MPM2;

    // AFLSource Pass
    llvm::errs() << "Running AFLSource Pass\n";
    MPM2.addPass(AFLSourcePass());
    MPM2.run(*mod, MAM);
    suffix = ".source.bc";
    
    goto exit_point;
  } else {
    // Parent process
    llvm::ModulePassManager MPM3;

    // TaintSink Pass
    llvm::errs() << "Running TaintSink Pass\n";
    MPM3.addPass(TaintSinkPass());
    MPM3.run(*mod, MAM);
    suffix = ".sink.bc";

    goto exit_point;
  }

exit_point:

  llvm::verifyModule(*mod, &llvm::errs());
  writeLLVMModuleToFile(*mod, suffix);
  errs() << "\n-------------\n End of Pass\n-------------\n";

  return 0;
}

